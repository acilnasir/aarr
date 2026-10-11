// Supabase Edge Function: "api"
// Pengganti Code.gs (Google Apps Script) yang sebelumnya berjalan di Google Sheets.
//
// Mendukung action lama (login, save, read, update, delete) PLUS struktur
// organisasi berjenjang nasional: UPT (kab/kota) -> KANWIL (provinsi) -> DITJEN
// (nasional). Setiap action sensitif kini memerlukan token sesi (dikembalikan
// oleh "login") yang ditandatangani HMAC-SHA256 di server, sehingga identitas
// & lingkup kewenangan pemanggil tidak bisa dipalsukan dari client.
//
// Deploy: supabase functions deploy api --no-verify-jwt
//
// Env vars SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY otomatis tersedia di
// runtime Edge Function Supabase, tidak perlu di-set manual.
// APP_SESSION_SECRET harus di-set manual lewat `supabase secrets set`.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
// compareSync/hashSync (bukan versi async) dipakai karena versi async memakai
// Worker, yang tidak tersedia di runtime Supabase Edge Functions.
import { compareSync, hashSync } from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SESSION_SECRET = Deno.env.get("APP_SESSION_SECRET") ?? "";

// Service role key -> bypass RLS, hanya dipakai di server (aman, tidak pernah dikirim ke browser).
const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 jam

type Tingkat = "UPT" | "KANWIL" | "DITJEN";

interface SessionPayload {
  username: string;
  nama: string;
  peran: string;
  tingkat: Tingkat;
  upt_id: string | null;
  kanwil_id: string | null;
  exp: number; // epoch ms
}

// ---------------------------------------------------------------------------
// Util: base64url + HMAC-SHA256 untuk token sesi (mirip JWT yang disederhanakan)
// ---------------------------------------------------------------------------
function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

let cachedKey: CryptoKey | null = null;
async function getHmacKey(): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  cachedKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  return cachedKey;
}

async function signToken(payload: SessionPayload): Promise<string> {
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await getHmacKey();
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return `${body}.${base64UrlEncode(new Uint8Array(sig))}`;
}

async function verifyToken(token: unknown): Promise<SessionPayload | null> {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  try {
    const key = await getHmacKey();
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(sig),
      new TextEncoder().encode(body),
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body))) as SessionPayload;
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function unauthorized(message = "Sesi tidak valid, silakan login ulang.") {
  return { success: false, message, code: "UNAUTHORIZED" };
}

function forbidden(message = "Anda tidak memiliki akses untuk aksi ini.") {
  return { success: false, message, code: "FORBIDDEN" };
}

// ---------------------------------------------------------------------------
// HTTP entrypoint
// ---------------------------------------------------------------------------
serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS_HEADERS });
  }

  try {
    const body = await req.json();
    const action = body.action;

    // Aksi yang tidak memerlukan sesi login sebelumnya.
    if (action === "login") {
      const result = await checkLogin(body.username, body.password);
      return json(result);
    }

    // Semua aksi lain memerlukan token sesi yang valid.
    const session = await verifyToken(body.token);
    if (!session) {
      return json(unauthorized());
    }

    let result: Record<string, unknown>;
    switch (action) {
      // --- Data asesmen (dibatasi lingkup organisasi) ---
      case "save":
        result = await saveDataAsesmen(session, body.payload, body.wali, body.nakes);
        break;
      case "read":
        result = await readDataAsesmen(session);
        break;
      case "exportAsesmen":
        result = isPimpinan(session)
          ? await readDataAsesmen(session)
          : forbidden("Hanya pimpinan yang dapat mengekspor data.");
        break;
      case "update":
        result = await updateDataAsesmen(session, body.id, body.payload, body.wali, body.nakes);
        break;
      case "delete":
        result = await deleteDataAsesmen(session, body.id);
        break;

      // --- Tanda tangan & pengesahan ---
      case "getMySignature":
        result = await getMySignature(session);
        break;
      case "saveMySignature":
        result = await saveMySignature(session, body.image);
        break;
      case "listPenandatangan":
        result = await listPenandatangan(session);
        break;
      case "getPengesahan":
        result = await getPengesahan(session, body.id);
        break;

      // --- Kunci aplikasi & dashboard eksekutif ---
      case "getKunci":
        result = await getKunci(session);
        break;
      case "setKunci":
        result = await setKunci(session, !!body.locked);
        break;
      case "getStatistik":
        result = await getStatistik(session, body.kanwil_id, body.upt_id);
        break;

      // --- Akun sendiri ---
      case "changePassword":
        result = await changePassword(session, body.currentPassword, body.newPassword);
        break;

      // --- Kelola Wilayah (Kanwil) ---
      case "listKanwil":
        result = await listKanwil(session);
        break;
      case "createKanwil":
        result = await createKanwil(session, body.payload);
        break;
      case "updateKanwil":
        result = await updateKanwil(session, body.id, body.payload);
        break;
      case "deleteKanwil":
        result = await deleteKanwil(session, body.id);
        break;

      // --- Kelola UPT ---
      case "listUpt":
        result = await listUpt(session);
        break;
      case "createUpt":
        result = await createUpt(session, body.payload);
        break;
      case "updateUpt":
        result = await updateUpt(session, body.id, body.payload);
        break;
      case "deleteUpt":
        result = await deleteUpt(session, body.id);
        break;

      // --- Profil Ditjen (singleton) ---
      case "getDitjenProfile":
        result = await getDitjenProfile(session);
        break;
      case "updateDitjenProfile":
        result = await updateDitjenProfile(session, body.payload);
        break;

      // --- Kelola User ---
      case "listUsers":
        result = await listUsers(session);
        break;
      case "createUser":
        result = await createUser(session, body.payload);
        break;
      case "updateUser":
        result = await updateUser(session, body.username, body.payload);
        break;
      case "deleteUser":
        result = await deleteUser(session, body.username);
        break;

      default:
        result = { success: false, message: "Aksi tidak dikenal." };
    }

    return json(result);
  } catch (error) {
    return json({ success: false, message: String(error) });
  }
});

function json(result: Record<string, unknown>) {
  return new Response(JSON.stringify(result), {
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

// Mengembalikan timestamp "yyyy-MM-dd HH:mm:ss" pada zona waktu Jakarta (GMT+7),
// identik dengan format ID yang dipakai Code.gs sebelumnya.
function nowJakartaTimestamp(): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Jakarta",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(new Date());

  const get = (type: string) => parts.find((p) => p.type === type)!.value;
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")}`;
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------
async function checkLogin(username: string, password: string) {
  const { data, error } = await supabase
    .from("users")
    .select("username, password_hash, nama, peran, tingkat, upt_id, kanwil_id")
    .eq("username", username)
    .maybeSingle();

  if (error || !data) {
    return { success: false, message: "Username/password salah!" };
  }

  const valid = compareSync(password, data.password_hash);
  if (!valid) {
    return { success: false, message: "Username/password salah!" };
  }

  const sessionPayload: SessionPayload = {
    username: data.username,
    nama: data.nama,
    peran: data.peran,
    tingkat: (data.tingkat ?? "UPT") as Tingkat,
    upt_id: data.upt_id,
    kanwil_id: data.kanwil_id,
    exp: Date.now() + SESSION_TTL_MS,
  };
  const token = await signToken(sessionPayload);

  return {
    success: true,
    token,
    user: {
      username: data.username,
      nama: data.nama,
      peran: data.peran,
      tingkat: sessionPayload.tingkat,
      upt_id: data.upt_id,
      kanwil_id: data.kanwil_id,
    },
  };
}

// ---------------------------------------------------------------------------
// Ganti password (akun sendiri)
// ---------------------------------------------------------------------------
async function changePassword(session: SessionPayload, currentPassword: string, newPassword: string) {
  if (!newPassword || String(newPassword).length < 6) {
    return { success: false, message: "Password baru minimal 6 karakter." };
  }

  const { data, error } = await supabase
    .from("users")
    .select("password_hash")
    .eq("username", session.username)
    .maybeSingle();

  if (error || !data) {
    return { success: false, message: "User tidak ditemukan." };
  }
  if (!compareSync(currentPassword ?? "", data.password_hash)) {
    return { success: false, message: "Password lama salah." };
  }

  const newHash = hashSync(newPassword);
  const { error: updError } = await supabase
    .from("users")
    .update({ password_hash: newHash })
    .eq("username", session.username);

  if (updError) {
    return { success: false, message: "Gagal mengubah password: " + updError.message };
  }
  return { success: true, message: "Password berhasil diubah." };
}

// ---------------------------------------------------------------------------
// Data Asesmen (payload[2] = No. Register, lihat submitData() di index.html)
// ---------------------------------------------------------------------------
function extractNoRegister(payload: unknown[]): string {
  return String(payload[2] ?? "").trim();
}

async function saveDataAsesmen(session: SessionPayload, payload: unknown[], wali?: string, nakes?: string) {
  if (session.tingkat !== "UPT") {
    return forbidden("Hanya user tingkat UPT yang dapat menginput data asesmen.");
  }
  if ((await lockStatus(session)).locked) return forbidden("Aplikasi sedang dikunci.");
  const id = nowJakartaTimestamp();
  const noRegister = extractNoRegister(payload);

  const { error } = await supabase.from("hasil_asesmen").insert({
    id,
    no_register: noRegister,
    payload,
    upt_id: session.upt_id, // selalu diisi dari sesi, bukan dari client
    asesor_username: session.username,
    wali_username: wali || null,
    nakes_username: nakes || null,
  });

  if (error) {
    return { success: false, message: "Gagal menyimpan: " + error.message };
  }
  return { success: true, message: "Data asesmen berhasil ditambahkan!" };
}

// Mengembalikan daftar id UPT yang boleh dilihat pemanggil (lingkup berjenjang).
async function scopedUptIds(session: SessionPayload): Promise<string[] | null> {
  // null berarti "tanpa filter" (DITJEN melihat semua).
  if (session.tingkat === "DITJEN") return null;
  if (session.tingkat === "UPT") return session.upt_id ? [session.upt_id] : [];

  // KANWIL: seluruh UPT dalam provinsi (kanwil) miliknya.
  const { data, error } = await supabase
    .from("upt")
    .select("id")
    .eq("kanwil_id", session.kanwil_id);
  if (error || !data) return [];
  return data.map((r) => r.id as string);
}

async function readDataAsesmen(session: SessionPayload) {
  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && uptIds.length === 0) {
    return { success: true, data: [] };
  }

  let query = supabase
    .from("hasil_asesmen")
    .select("id, payload, upt_id, wali_username, nakes_username, updated_at, upt:upt_id(nama, kanwil:kanwil_id(nama))")
    .order("created_at", { ascending: false });
  if (uptIds !== null) {
    query = query.in("upt_id", uptIds);
  }

  const { data, error } = await query;
  if (error) {
    return { success: false, message: "Gagal membaca data: " + error.message };
  }

  // Bentuk ulang menjadi array [id, ...payload, upt_nama, kanwil_nama] agar
  // tetap identik (di 0..N) dengan format lama dari Google Sheets -- 2 kolom
  // tambahan di ujung dipakai khusus oleh dashboard pemantauan Kanwil/Ditjen.
  // deno-lint-ignore no-explicit-any
  const records = (data ?? []).map((row: any) => [
    row.id,
    ...(row.payload as unknown[]),
    row.upt?.nama ?? "",
    row.upt?.kanwil?.nama ?? "",
    row.wali_username ?? "",
    row.nakes_username ?? "",
    row.updated_at ?? "",
  ]);
  return { success: true, data: records };
}

async function updateDataAsesmen(session: SessionPayload, idNoreg: string, payload: unknown[], wali?: string, nakes?: string) {
  if (session.tingkat !== "UPT") {
    return forbidden("Hanya user tingkat UPT yang dapat mengubah data asesmen.");
  }
  if ((await lockStatus(session)).locked) return forbidden("Aplikasi sedang dikunci.");
  const target = String(idNoreg).trim();
  const newNoRegister = extractNoRegister(payload);

  const { data: existing, error: findError } = await supabase
    .from("hasil_asesmen")
    .select("id, upt_id")
    .eq("no_register", target)
    .maybeSingle();

  if (findError || !existing) {
    return { success: false, message: "Gagal update. No. Register tidak ditemukan di database." };
  }
  if (existing.upt_id !== session.upt_id) {
    return forbidden("Data ini bukan milik UPT Anda.");
  }

  const { error: updateError } = await supabase
    .from("hasil_asesmen")
    .update({ no_register: newNoRegister, payload, wali_username: wali || null, nakes_username: nakes || null })
    .eq("id", existing.id);

  if (updateError) {
    return { success: false, message: "Gagal update: " + updateError.message };
  }
  return { success: true, message: "Data asesmen berhasil diperbarui (ditimpa)!" };
}

async function deleteDataAsesmen(session: SessionPayload, idNoreg: string) {
  if (session.tingkat !== "UPT") {
    return forbidden("Hanya user tingkat UPT yang dapat menghapus data asesmen.");
  }
  if ((await lockStatus(session)).locked) return forbidden("Aplikasi sedang dikunci.");
  const target = String(idNoreg).trim();

  const { data: existing, error: findError } = await supabase
    .from("hasil_asesmen")
    .select("id, upt_id")
    .eq("no_register", target)
    .maybeSingle();

  if (findError || !existing) {
    return { success: false, message: "Gagal hapus. No. Register tidak ditemukan." };
  }
  if (existing.upt_id !== session.upt_id) {
    return forbidden("Data ini bukan milik UPT Anda.");
  }

  const { error: deleteError } = await supabase
    .from("hasil_asesmen")
    .delete()
    .eq("id", existing.id);

  if (deleteError) {
    return { success: false, message: "Gagal hapus: " + deleteError.message };
  }
  return { success: true, message: "Data berhasil dihapus!" };
}

// ---------------------------------------------------------------------------
// Tanda tangan & pengesahan
// ---------------------------------------------------------------------------
const MAX_SIGNATURE_LENGTH = 400_000; // karakter data URL (~300 KB)

async function getMySignature(session: SessionPayload) {
  const { data, error } = await supabase
    .from("users")
    .select("tanda_tangan")
    .eq("username", session.username)
    .maybeSingle();
  if (error) return { success: false, message: error.message };
  return { success: true, image: data?.tanda_tangan ?? null };
}

// image = data URL PNG/JPEG, atau null untuk menghapus tanda tangan.
async function saveMySignature(session: SessionPayload, image: unknown) {
  if (image !== null && image !== undefined && image !== "") {
    if (
      typeof image !== "string" ||
      !/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(image)
    ) {
      return { success: false, message: "Format gambar harus PNG atau JPEG." };
    }
    if (image.length > MAX_SIGNATURE_LENGTH) {
      return { success: false, message: "Ukuran gambar terlalu besar." };
    }
  }
  const { error } = await supabase
    .from("users")
    .update({ tanda_tangan: image || null })
    .eq("username", session.username);
  if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
  return { success: true, message: image ? "Tanda tangan berhasil disimpan." : "Tanda tangan dihapus." };
}

// Daftar user pada UPT pemanggil yang bisa dipilih sebagai wali / tenaga kesehatan.
async function listPenandatangan(session: SessionPayload) {
  if (session.tingkat !== "UPT" || !session.upt_id) return forbidden();
  const { data, error } = await supabase
    .from("users")
    .select("username, nama, peran, tanda_tangan")
    .eq("upt_id", session.upt_id)
    .order("nama");
  if (error) return { success: false, message: error.message };
  // deno-lint-ignore no-explicit-any
  return {
    success: true,
    // deno-lint-ignore no-explicit-any
    data: (data ?? []).map((u: any) => ({
      username: u.username,
      nama: u.nama,
      peran: u.peran,
      has_ttd: !!u.tanda_tangan,
    })),
  };
}

// Data pengesahan (nama + gambar tanda tangan) untuk satu asesmen, dengan
// pembatasan lingkup yang sama seperti readDataAsesmen.
async function getPengesahan(session: SessionPayload, idNoreg: string) {
  const { data: rec, error } = await supabase
    .from("hasil_asesmen")
    .select("upt_id, payload, asesor_username, wali_username, nakes_username")
    .eq("no_register", String(idNoreg).trim())
    .maybeSingle();
  if (error || !rec) return { success: false, message: "Data asesmen tidak ditemukan." };

  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && !uptIds.includes(rec.upt_id)) return forbidden();

  const fetchUser = async (username: string | null) => {
    if (!username) return null;
    const { data } = await supabase
      .from("users")
      .select("username, nama, peran, tanda_tangan")
      .eq("username", username)
      .maybeSingle();
    return data ?? null;
  };

  let asesor = await fetchUser(rec.asesor_username);
  if (!asesor) {
    // Data lama tanpa asesor_username: cocokkan nama asesor pada UPT yang sama.
    const nama = (rec.payload as unknown[])[0];
    const { data } = await supabase
      .from("users")
      .select("username, nama, peran, tanda_tangan")
      .eq("upt_id", rec.upt_id)
      .eq("nama", nama)
      .maybeSingle();
    asesor = data ?? null;
  }

  return {
    success: true,
    asesor,
    wali: await fetchUser(rec.wali_username),
    nakes: await fetchUser(rec.nakes_username),
  };
}

// ---------------------------------------------------------------------------
// Kunci aplikasi (tutup/buka input asesmen)
//   Kepala Bapas -> mengunci UPT-nya; Kanwil -> seluruh UPT di provinsinya;
//   Ditjen -> seluruh UPT nasional. Kunci terkuat dari atas yang berlaku.
// ---------------------------------------------------------------------------
// Pimpinan tertinggi per tingkat: Kepala Bapas (UPT), Kepala Kanwil, Dirjen/admin Ditjen.
function isPimpinan(session: SessionPayload): boolean {
  const peran = (session.peran ?? "").trim().toLowerCase();
  if (session.tingkat === "UPT") return peran === "kepala bapas";
  if (session.tingkat === "KANWIL") return peran.includes("kepala");
  return /direktur|dirjen|admin/.test(peran);
}

function isKepalaBapas(session: SessionPayload): boolean {
  return session.tingkat === "UPT" && (session.peran ?? "").trim().toLowerCase() === "kepala bapas";
}

// Daftar lingkup yang berlaku bagi pemanggil, dari tertinggi ke terendah.
async function lockScopes(session: SessionPayload): Promise<{ scope: Tingkat; ref: string }[]> {
  const scopes: { scope: Tingkat; ref: string }[] = [{ scope: "DITJEN", ref: "" }];
  if (session.tingkat === "KANWIL" && session.kanwil_id) {
    scopes.push({ scope: "KANWIL", ref: session.kanwil_id });
  } else if (session.tingkat === "UPT" && session.upt_id) {
    const { data } = await supabase.from("upt").select("kanwil_id").eq("id", session.upt_id).maybeSingle();
    if (data?.kanwil_id) scopes.push({ scope: "KANWIL", ref: data.kanwil_id });
    scopes.push({ scope: "UPT", ref: session.upt_id });
  }
  return scopes;
}

async function lockStatus(session: SessionPayload) {
  const scopes = await lockScopes(session);
  const { data } = await supabase.from("kunci_aplikasi").select("scope, ref_id, locked").eq("locked", true);
  const active = new Set((data ?? []).map((r) => `${r.scope}:${r.ref_id}`));
  const hit = scopes.find((s) => active.has(`${s.scope}:${s.ref}`));
  const own = scopes[scopes.length - 1];
  return {
    locked: !!hit,
    locked_by: hit?.scope ?? null,
    own_locked: active.has(`${own.scope}:${own.ref}`),
    own_scope: own,
  };
}

async function getKunci(session: SessionPayload) {
  const st = await lockStatus(session);
  const canToggle = (session.tingkat !== "UPT" || isKepalaBapas(session)) &&
    (st.locked_by === null || st.locked_by === st.own_scope.scope);
  return {
    success: true,
    locked: st.locked,
    locked_by: st.locked_by,
    own_locked: st.own_locked,
    can_toggle: canToggle,
    scope: st.own_scope.scope,
  };
}

async function setKunci(session: SessionPayload, locked: boolean) {
  if (session.tingkat === "UPT" && !isKepalaBapas(session)) {
    return forbidden("Hanya Kepala Bapas yang dapat mengunci/membuka aplikasi.");
  }
  const st = await lockStatus(session);
  if (st.locked_by && st.locked_by !== st.own_scope.scope) {
    return forbidden("Aplikasi dikunci oleh tingkat yang lebih tinggi.");
  }
  const { error } = await supabase.from("kunci_aplikasi").upsert({
    scope: st.own_scope.scope,
    ref_id: st.own_scope.ref,
    locked,
    updated_by: session.username,
    updated_at: new Date().toISOString(),
  });
  if (error) return { success: false, message: "Gagal mengubah status: " + error.message };
  return { success: true, locked, message: locked ? "Aplikasi dikunci." : "Aplikasi dibuka." };
}

// ---------------------------------------------------------------------------
// Dashboard eksekutif (Kepala Bapas, Kanwil, Ditjen)
// Indeks payload: [0]=asesor [5]=usia [24]=zat [101]=skor [102]=kategori
// [103]=klaster [104]=sidang TPP (lihat submitData() di index.html).
// ---------------------------------------------------------------------------
function countBy(rows: unknown[][], idx: number): Record<string, number> {
  const out: Record<string, number> = {};
  for (const p of rows) {
    const k = String(p[idx] ?? "").trim() || "-";
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function summarize(groups: Map<string, { nama: string; payloads: unknown[][] }>) {
  return [...groups.values()].map((g) => {
    const kat = countBy(g.payloads, 102);
    const skor = g.payloads.map((p) => parseFloat(String(p[101])) || 0);
    return {
      nama: g.nama,
      total: g.payloads.length,
      layak: kat["LAYAK"] ?? 0,
      bersyarat: kat["LAYAK BERSYARAT"] ?? 0,
      tidak: kat["TIDAK LAYAK"] ?? 0,
      ditunda: kat["DITUNDA"] ?? 0,
      rata_skor: skor.length ? Math.round((skor.reduce((a, b) => a + b, 0) / skor.length) * 10) / 10 : 0,
    };
  }).sort((a, b) => b.total - a.total);
}

async function getStatistik(session: SessionPayload, kanwilFilter?: string, uptFilter?: string) {
  if (session.tingkat === "UPT" && !isKepalaBapas(session)) {
    return forbidden("Dashboard eksekutif hanya untuk Kepala Bapas, Kanwil, dan Ditjen.");
  }

  // Daftar UPT dalam lingkup pemanggil (untuk opsi filter & pembatasan).
  let uptQuery = supabase.from("upt").select("id, nama, kanwil_id, kanwil:kanwil_id(id, nama)").order("nama");
  if (session.tingkat === "UPT") uptQuery = uptQuery.eq("id", session.upt_id);
  else if (session.tingkat === "KANWIL") uptQuery = uptQuery.eq("kanwil_id", session.kanwil_id);
  const { data: uptList, error: uptErr } = await uptQuery;
  if (uptErr) return { success: false, message: uptErr.message };
  // deno-lint-ignore no-explicit-any
  let scopeUpts = (uptList ?? []) as any[];
  if (session.tingkat === "DITJEN" && kanwilFilter) scopeUpts = scopeUpts.filter((u) => u.kanwil_id === kanwilFilter);
  if (session.tingkat !== "UPT" && uptFilter) scopeUpts = scopeUpts.filter((u) => u.id === uptFilter);
  const uptIds = scopeUpts.map((u) => u.id as string);

  // deno-lint-ignore no-explicit-any
  const records: any[] = [];
  if (uptIds.length > 0) {
    const PAGE = 1000;
    for (let from = 0; ; from += PAGE) {
      const { data, error } = await supabase
        .from("hasil_asesmen")
        .select("payload, created_at, updated_at, upt_id")
        .in("upt_id", uptIds)
        .order("created_at")
        .range(from, from + PAGE - 1);
      if (error) return { success: false, message: error.message };
      records.push(...(data ?? []));
      if (!data || data.length < PAGE) break;
    }
  }

  const payloads = records.map((r) => r.payload as unknown[]);
  const skor = payloads.map((p) => parseFloat(String(p[101])) || 0);
  const rata = skor.length ? Math.round((skor.reduce((a, b) => a + b, 0) / skor.length) * 10) / 10 : 0;

  const usia = { "<=20": 0, "21-30": 0, "31-40": 0, "41-50": 0, ">50": 0, "-": 0 } as Record<string, number>;
  for (const p of payloads) {
    const u = parseInt(String(p[5]));
    const k = isNaN(u) ? "-" : u <= 20 ? "<=20" : u <= 30 ? "21-30" : u <= 40 ? "31-40" : u <= 50 ? "41-50" : ">50";
    usia[k]++;
  }

  const bulanan: Record<string, number> = {};
  for (const r of records) {
    const b = String(r.created_at).slice(0, 7);
    bulanan[b] = (bulanan[b] ?? 0) + 1;
  }
  const weekAgo = Date.now() - 7 * 86400000;

  const group = (keyOf: (r: any) => [string, string]) => { // deno-lint-ignore no-explicit-any
    const m = new Map<string, { nama: string; payloads: unknown[][] }>();
    for (const r of records) {
      const [k, nama] = keyOf(r);
      if (!m.has(k)) m.set(k, { nama, payloads: [] });
      m.get(k)!.payloads.push(r.payload as unknown[]);
    }
    return summarize(m);
  };
  const uptById = new Map(scopeUpts.map((u) => [u.id as string, u]));

  const result: Record<string, unknown> = {
    success: true,
    tingkat: session.tingkat,
    total: records.length,
    rata_skor: rata,
    diedit_7hari: records.filter((r) => new Date(r.updated_at).getTime() >= weekAgo && r.updated_at !== r.created_at).length,
    jumlah_upt: scopeUpts.length,
    kategori: countBy(payloads, 102),
    klaster: countBy(payloads, 103),
    tpp: countBy(payloads, 104),
    zat: countBy(payloads, 24),
    usia,
    bulanan: Object.entries(bulanan).sort().slice(-12).map(([bulan, n]) => ({ bulan, n })),
    per_upt: group((r) => [r.upt_id, uptById.get(r.upt_id)?.nama ?? "-"]),
    options: {
      kanwil: session.tingkat === "DITJEN"
        ? [...new Map((uptList ?? []).map((u: any) => [u.kanwil?.id, u.kanwil?.nama])).entries()] // deno-lint-ignore no-explicit-any
          .filter(([id]) => id).map(([id, nama]) => ({ id, nama }))
        : [],
      upt: (uptList ?? []).map((u: any) => ({ id: u.id, nama: u.nama, kanwil_id: u.kanwil_id })), // deno-lint-ignore no-explicit-any
    },
  };
  if (session.tingkat === "DITJEN") {
    result.per_kanwil = group((r) => {
      const u = uptById.get(r.upt_id);
      return [u?.kanwil_id ?? "-", u?.kanwil?.nama ?? "-"];
    });
  }
  if (session.tingkat === "UPT") {
    result.per_asesor = group((r) => {
      const a = String((r.payload as unknown[])[0] ?? "-");
      return [a, a];
    });
  }
  return result;
}

// ---------------------------------------------------------------------------
// Kelola Wilayah (Kanwil) -- DITJEN: CRUD penuh. KANWIL: hanya lihat profil sendiri.
// ---------------------------------------------------------------------------
async function listKanwil(session: SessionPayload) {
  if (session.tingkat === "UPT") return forbidden();

  let query = supabase.from("kanwil").select("*").order("nama");
  if (session.tingkat === "KANWIL") {
    query = query.eq("id", session.kanwil_id);
  }
  const { data, error } = await query;
  if (error) return { success: false, message: error.message };
  return { success: true, data };
}

async function createKanwil(session: SessionPayload, payload: Record<string, unknown>) {
  if (session.tingkat !== "DITJEN") return forbidden("Hanya Ditjen yang dapat membuat Kanwil.");
  const { nama, provinsi, alamat, kepala } = payload;
  if (!nama || !provinsi) return { success: false, message: "Nama dan provinsi wajib diisi." };

  const { data, error } = await supabase
    .from("kanwil")
    .insert({ nama, provinsi, alamat, kepala })
    .select()
    .single();
  if (error) return { success: false, message: error.message };
  return { success: true, message: "Kanwil berhasil ditambahkan.", data };
}

async function updateKanwil(session: SessionPayload, id: string, payload: Record<string, unknown>) {
  if (session.tingkat !== "DITJEN") return forbidden("Hanya Ditjen yang dapat mengubah profil Kanwil.");
  const { nama, provinsi, alamat, kepala } = payload;

  const { error } = await supabase
    .from("kanwil")
    .update({ nama, provinsi, alamat, kepala, updated_at: new Date().toISOString() })
    .eq("id", id);
  if (error) return { success: false, message: error.message };
  return { success: true, message: "Kanwil berhasil diperbarui." };
}

async function deleteKanwil(session: SessionPayload, id: string) {
  if (session.tingkat !== "DITJEN") return forbidden("Hanya Ditjen yang dapat menghapus Kanwil.");

  const { error } = await supabase.from("kanwil").delete().eq("id", id);
  if (error) {
    return { success: false, message: "Gagal hapus (pastikan tidak ada UPT yang masih terhubung): " + error.message };
  }
  return { success: true, message: "Kanwil berhasil dihapus." };
}

// ---------------------------------------------------------------------------
// Kelola UPT -- DITJEN: CRUD penuh. KANWIL: hanya lihat & ubah UPT di provinsinya.
// ---------------------------------------------------------------------------
async function listUpt(session: SessionPayload) {
  if (session.tingkat === "UPT") return forbidden();

  let query = supabase.from("upt").select("*, kanwil:kanwil_id(nama, provinsi)").order("nama");
  if (session.tingkat === "KANWIL") {
    query = query.eq("kanwil_id", session.kanwil_id);
  }
  const { data, error } = await query;
  if (error) return { success: false, message: error.message };
  return { success: true, data };
}

async function createUpt(session: SessionPayload, payload: Record<string, unknown>) {
  if (session.tingkat !== "DITJEN") return forbidden("Hanya Ditjen yang dapat membuat UPT baru.");
  const { kanwil_id, nama, jenis, alamat, kepala } = payload;
  if (!kanwil_id || !nama || !jenis) {
    return { success: false, message: "Kanwil, nama, dan jenis UPT wajib diisi." };
  }

  const { data, error } = await supabase
    .from("upt")
    .insert({ kanwil_id, nama, jenis, alamat, kepala })
    .select()
    .single();
  if (error) return { success: false, message: error.message };
  return { success: true, message: "UPT berhasil ditambahkan.", data };
}

async function updateUpt(session: SessionPayload, id: string, payload: Record<string, unknown>) {
  if (session.tingkat === "UPT") return forbidden();

  // Kanwil hanya boleh mengubah UPT di provinsinya sendiri.
  if (session.tingkat === "KANWIL") {
    const { data: existing, error: findError } = await supabase
      .from("upt")
      .select("kanwil_id")
      .eq("id", id)
      .maybeSingle();
    if (findError || !existing) return { success: false, message: "UPT tidak ditemukan." };
    if (existing.kanwil_id !== session.kanwil_id) {
      return forbidden("UPT ini berada di luar provinsi Anda.");
    }
  }

  const { nama, jenis, alamat, kepala } = payload;
  const update: Record<string, unknown> = { nama, jenis, alamat, kepala, updated_at: new Date().toISOString() };
  // Hanya Ditjen yang boleh memindahkan UPT ke Kanwil lain.
  if (session.tingkat === "DITJEN" && payload.kanwil_id) update.kanwil_id = payload.kanwil_id;

  const { error } = await supabase.from("upt").update(update).eq("id", id);
  if (error) return { success: false, message: error.message };
  return { success: true, message: "UPT berhasil diperbarui." };
}

async function deleteUpt(session: SessionPayload, id: string) {
  if (session.tingkat !== "DITJEN") return forbidden("Hanya Ditjen yang dapat menghapus UPT.");

  const { error } = await supabase.from("upt").delete().eq("id", id);
  if (error) {
    return { success: false, message: "Gagal hapus (pastikan tidak ada user/data asesmen yang masih terhubung): " + error.message };
  }
  return { success: true, message: "UPT berhasil dihapus." };
}

// ---------------------------------------------------------------------------
// Profil Ditjen (singleton) -- DITJEN: lihat & ubah. KANWIL: lihat saja.
// ---------------------------------------------------------------------------
async function getDitjenProfile(session: SessionPayload) {
  if (session.tingkat === "UPT") return forbidden();

  const { data, error } = await supabase.from("ditjen_profile").select("*").eq("id", 1).maybeSingle();
  if (error) return { success: false, message: error.message };
  return { success: true, data };
}

async function updateDitjenProfile(session: SessionPayload, payload: Record<string, unknown>) {
  if (session.tingkat !== "DITJEN") return forbidden("Hanya Ditjen yang dapat mengubah profil ini.");
  const { nama, alamat, dirjen } = payload;

  const { error } = await supabase
    .from("ditjen_profile")
    .update({ nama, alamat, dirjen, updated_at: new Date().toISOString() })
    .eq("id", 1);
  if (error) return { success: false, message: error.message };
  return { success: true, message: "Profil Ditjen berhasil diperbarui." };
}

// ---------------------------------------------------------------------------
// Kelola User -- DITJEN: semua user. KANWIL: user UPT di provinsinya + user
// KANWIL lain di provinsi yang sama (tidak termasuk user DITJEN).
// ---------------------------------------------------------------------------
async function listUsers(session: SessionPayload) {
  if (session.tingkat === "UPT" && !isKepalaBapas(session)) return forbidden();

  const selectCols = "username, nama, peran, tingkat, upt_id, kanwil_id, upt:upt_id(nama), kanwil:kanwil_id(nama)";

  if (session.tingkat === "UPT") {
    const { data, error } = await supabase.from("users").select(selectCols).eq("upt_id", session.upt_id).order("username");
    if (error) return { success: false, message: error.message };
    return { success: true, data };
  }

  if (session.tingkat === "DITJEN") {
    const { data, error } = await supabase.from("users").select(selectCols).order("username");
    if (error) return { success: false, message: error.message };
    return { success: true, data };
  }

  // KANWIL: ambil daftar id UPT di provinsinya dulu.
  const { data: uptRows, error: uptError } = await supabase
    .from("upt")
    .select("id")
    .eq("kanwil_id", session.kanwil_id);
  if (uptError) return { success: false, message: uptError.message };
  const uptIds = (uptRows ?? []).map((r) => r.id as string);

  const orFilter = [
    `kanwil_id.eq.${session.kanwil_id}`,
    uptIds.length > 0 ? `upt_id.in.(${uptIds.join(",")})` : null,
  ].filter(Boolean).join(",");

  const { data, error } = await supabase.from("users").select(selectCols).or(orFilter).order("username");
  if (error) return { success: false, message: error.message };
  return { success: true, data };
}

// Memastikan pemanggil (jika KANWIL) berwenang atas tingkat/unit target.
async function canManageTargetUser(
  session: SessionPayload,
  tingkat: Tingkat,
  upt_id: string | null,
  kanwil_id: string | null,
): Promise<boolean> {
  if (session.tingkat === "DITJEN") return true;
  // Kepala Bapas: hanya user tingkat UPT pada UPT-nya sendiri.
  if (isKepalaBapas(session)) return tingkat === "UPT" && !!upt_id && upt_id === session.upt_id;
  if (session.tingkat !== "KANWIL") return false;
  if (tingkat === "DITJEN") return false;
  if (tingkat === "KANWIL") return kanwil_id === session.kanwil_id;
  // tingkat === "UPT": UPT target harus berada di provinsi (kanwil) yang sama.
  if (!upt_id) return false;
  const { data } = await supabase.from("upt").select("kanwil_id").eq("id", upt_id).maybeSingle();
  return !!data && data.kanwil_id === session.kanwil_id;
}

async function createUser(session: SessionPayload, payload: Record<string, unknown>) {
  if (session.tingkat === "UPT" && !isKepalaBapas(session)) return forbidden();
  const { username, password, nama, peran, tingkat, upt_id, kanwil_id } = payload as {
    username: string; password: string; nama: string; peran: string;
    tingkat: Tingkat; upt_id: string | null; kanwil_id: string | null;
  };
  if (!username || !password || !nama || !tingkat) {
    return { success: false, message: "Username, password, nama, dan tingkat wajib diisi." };
  }

  const allowed = await canManageTargetUser(session, tingkat, upt_id ?? null, kanwil_id ?? null);
  if (!allowed) return forbidden("Anda tidak berwenang membuat user dengan lingkup ini.");

  const { error } = await supabase.from("users").insert({
    username,
    password_hash: hashSync(password),
    nama,
    peran: peran ?? "",
    tingkat,
    upt_id: tingkat === "UPT" ? upt_id : null,
    kanwil_id: tingkat === "KANWIL" ? kanwil_id : null,
  });
  if (error) return { success: false, message: "Gagal menambah user: " + error.message };
  return { success: true, message: "User berhasil ditambahkan." };
}

async function updateUser(session: SessionPayload, username: string, payload: Record<string, unknown>) {
  if (session.tingkat === "UPT" && !isKepalaBapas(session)) return forbidden();

  const { data: existing, error: findError } = await supabase
    .from("users")
    .select("tingkat, upt_id, kanwil_id")
    .eq("username", username)
    .maybeSingle();
  if (findError || !existing) return { success: false, message: "User tidak ditemukan." };

  const allowedExisting = await canManageTargetUser(session, existing.tingkat, existing.upt_id, existing.kanwil_id);
  if (!allowedExisting) return forbidden("Anda tidak berwenang mengubah user ini.");

  const { nama, peran, password, tingkat, upt_id, kanwil_id } = payload as {
    nama?: string; peran?: string; password?: string;
    tingkat?: Tingkat; upt_id?: string | null; kanwil_id?: string | null;
  };

  const newTingkat = tingkat ?? existing.tingkat;
  const newUptId = newTingkat === "UPT" ? (upt_id ?? existing.upt_id) : null;
  const newKanwilId = newTingkat === "KANWIL" ? (kanwil_id ?? existing.kanwil_id) : null;
  const allowedNew = await canManageTargetUser(session, newTingkat, newUptId, newKanwilId);
  if (!allowedNew) return forbidden("Anda tidak berwenang memindahkan user ke lingkup tersebut.");

  const update: Record<string, unknown> = {
    nama, peran, tingkat: newTingkat, upt_id: newUptId, kanwil_id: newKanwilId,
  };
  if (password) update.password_hash = hashSync(password);

  const { error } = await supabase.from("users").update(update).eq("username", username);
  if (error) return { success: false, message: "Gagal mengubah user: " + error.message };
  return { success: true, message: "User berhasil diperbarui." };
}

async function deleteUser(session: SessionPayload, username: string) {
  if (session.tingkat === "UPT" && !isKepalaBapas(session)) return forbidden();
  if (username === session.username) return { success: false, message: "Tidak dapat menghapus akun sendiri." };

  const { data: existing, error: findError } = await supabase
    .from("users")
    .select("tingkat, upt_id, kanwil_id")
    .eq("username", username)
    .maybeSingle();
  if (findError || !existing) return { success: false, message: "User tidak ditemukan." };

  const allowed = await canManageTargetUser(session, existing.tingkat, existing.upt_id, existing.kanwil_id);
  if (!allowed) return forbidden("Anda tidak berwenang menghapus user ini.");

  const { error } = await supabase.from("users").delete().eq("username", username);
  if (error) return { success: false, message: "Gagal menghapus user: " + error.message };
  return { success: true, message: "User berhasil dihapus." };
}
