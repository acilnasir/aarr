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

    // Aksi publik untuk halaman presensi klien (tanpa login, hanya data minimal).
    if (action === "publicCekKlien") return json(await publicCekKlien(body.no_register));
    if (action === "publicPresensi") return json(await publicPresensi(body));

    // Semua aksi lain memerlukan token sesi yang valid.
    const session = await verifyToken(body.token);
    if (!session) {
      return json(unauthorized());
    }

    let result: Record<string, unknown>;
    switch (action) {
      // --- Data asesmen (dibatasi lingkup organisasi) ---
      case "save":
        result = await saveDataAsesmen(session, body.payload, body);
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
        result = await updateDataAsesmen(session, body.id, body.payload, body);
        break;
      case "delete":
        result = await deleteDataAsesmen(session, body.id);
        break;

      // --- Tanda tangan & pengesahan ---
      case "getMySignature":
        result = await getMySignature(session);
        break;
      case "getMyPhoto":
        result = await getMyPhoto(session);
        break;
      case "saveMyPhoto":
        result = await saveMyPhoto(session, body.image);
        break;
      case "saveMySignature":
        result = await saveMySignature(session, body.image);
        break;
      case "listPenandatangan":
        result = await listPenandatangan(session, body.upt_id);
        break;
      case "listWilayahKerja":
        result = await listWilayahKerja(session);
        break;
      case "setWilayahKerja":
        result = await setWilayahKerja(session, body.bapas_id, body.upt_ids);
        break;
      case "getLokasiAsesmen":
        result = await getLokasiAsesmen(session);
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

      // --- Modul Registrasi: klien Bapas ---
      case "listKlien":
        result = await listKlien(session);
        break;
      case "getKlien":
        result = await getKlien(session, body.id);
        break;
      case "createKlien":
        result = await createKlien(session, body.payload);
        break;
      case "updateKlien":
        result = await updateKlien(session, body.id, body.payload);
        break;
      case "deleteKlien":
        result = await deleteKlien(session, body.id);
        break;

      // --- Modul Pengawasan: pelacakan klien ---
      case "listLokasiKlien":
        result = await listLokasiKlien(session);
        break;
      case "listRiwayatPresensi":
        result = await listRiwayatPresensi(session, body.klien_id);
        break;
      case "getFotoPresensi":
        result = await getFotoPresensi(session, body.id);
        break;
      case "saveWilayahKlien":
        result = await saveWilayahKlien(session, body.id, body.payload);
        break;

      // --- Modul Litmas ---
      case "listLitmas":
        result = await listLitmas(session);
        break;
      case "getLitmas":
        result = await getLitmas(session, body.id);
        break;
      case "saveLitmas":
        result = await saveLitmas(session, body.id, body.payload);
        break;
      case "deleteLitmas":
        result = await deleteLitmas(session, body.id);
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

const JENIS_BAPAS = "Balai Pemasyarakatan";

type UptRow = { id: string; nama: string; jenis: string; kanwil_id: string };

async function getUptRow(id: string | null | undefined): Promise<UptRow | null> {
  if (!id) return null;
  const { data } = await supabase.from("upt").select("id, nama, jenis, kanwil_id").eq("id", id).maybeSingle();
  return (data as UptRow | null) ?? null;
}

// Wilayah kerja (Lapas/Rutan/LPKA) dari sebuah Bapas.
async function wilayahKerjaOf(bapasId: string): Promise<UptRow[]> {
  const { data } = await supabase
    .from("bapas_wilayah_kerja")
    .select("upt:upt_id(id, nama, jenis, kanwil_id)")
    .eq("bapas_id", bapasId);
  // deno-lint-ignore no-explicit-any
  return ((data ?? []) as any[]).map((r) => r.upt).filter(Boolean);
}

// Bapas yang wilayah kerjanya mencakup UPT tertentu.
async function coveringBapas(uptId: string): Promise<UptRow[]> {
  const { data } = await supabase
    .from("bapas_wilayah_kerja")
    .select("bapas:bapas_id(id, nama, jenis, kanwil_id)")
    .eq("upt_id", uptId);
  // deno-lint-ignore no-explicit-any
  return ((data ?? []) as any[]).map((r) => r.bapas).filter(Boolean);
}

// Lokasi (UPT tempat WBP berada) yang boleh dipilih pemanggil: UPT sendiri,
// ditambah wilayah kerja bila pemanggil berada di Bapas.
async function lokasiAsesmenOptions(session: SessionPayload) {
  const own = await getUptRow(session.upt_id);
  if (!own) return { own: null, is_bapas: false, wilayah: [] as UptRow[] };
  const isBapas = own.jenis === JENIS_BAPAS;
  return { own, is_bapas: isBapas, wilayah: isBapas ? await wilayahKerjaOf(own.id) : [] };
}

async function getLokasiAsesmen(session: SessionPayload) {
  if (session.tingkat !== "UPT") return forbidden();
  const o = await lokasiAsesmenOptions(session);
  return { success: true, own: o.own, is_bapas: o.is_bapas, wilayah: o.wilayah };
}

// Pemanggil boleh menginput/mengedit/menghapus bila UPT-nya adalah pemilik
// data (lokasi WBP) atau UPT asal asesor.
function canEditRecord(session: SessionPayload, rec: { upt_id: string; asesor_upt_id?: string | null }): boolean {
  if (session.tingkat !== "UPT" || !session.upt_id) return false;
  return rec.upt_id === session.upt_id || rec.asesor_upt_id === session.upt_id;
}

// Wali/nakes harus pegawai UPT tempat WBP berada; asesor boleh dari UPT itu
// atau dari Bapas yang wilayah kerjanya mencakup UPT tersebut.
async function validateSigners(
  uptId: string,
  s: { wali?: string | null; nakes?: string | null; asesor?: string | null },
): Promise<{ ok: true; asesorUptId: string | null } | { ok: false; message: string }> {
  const userInfo = async (username: string) => {
    const { data } = await supabase.from("users").select("upt_id, status_penandatangan").eq("username", username).maybeSingle();
    return data as { upt_id: string | null; status_penandatangan: string[] } | null;
  };
  for (const [label, key, u] of [["Wali", "wali", s.wali], ["Tenaga kesehatan", "nakes", s.nakes]] as const) {
    if (!u) continue;
    const info = await userInfo(u);
    if (info?.upt_id !== uptId) return { ok: false, message: `${label} harus pegawai UPT tempat WBP berada.` };
    if (!info.status_penandatangan.includes(key)) return { ok: false, message: `${label} yang dipilih belum berstatus ${key} pada data user.` };
  }
  let asesorUptId: string | null = null;
  if (s.asesor) {
    const ai = await userInfo(s.asesor);
    const au = ai?.upt_id;
    if (!au) return { ok: false, message: "Asesor tidak ditemukan." };
    if (!ai.status_penandatangan.includes("asesor")) return { ok: false, message: "User yang dipilih belum berstatus asesor." };
    if (au !== uptId) {
      const bapasIds = (await coveringBapas(uptId)).map((b) => b.id);
      if (!bapasIds.includes(au)) {
        return { ok: false, message: "Asesor harus dari UPT tempat WBP berada atau Bapas yang mencakup wilayah kerjanya." };
      }
      asesorUptId = au;
    }
  }
  return { ok: true, asesorUptId };
}

type SaveExtra = { wali?: string; nakes?: string; asesor?: string; lokasi_upt_id?: string };

async function saveDataAsesmen(session: SessionPayload, payload: unknown[], extra: SaveExtra) {
  if (session.tingkat !== "UPT") {
    return forbidden("Hanya user tingkat UPT yang dapat menginput data asesmen.");
  }
  if ((await lockStatus(session)).locked) return forbidden("Aplikasi sedang dikunci.");

  // Lokasi WBP: UPT sendiri, atau (untuk user Bapas) salah satu wilayah kerjanya.
  let uptId = session.upt_id;
  if (extra.lokasi_upt_id && extra.lokasi_upt_id !== session.upt_id) {
    const o = await lokasiAsesmenOptions(session);
    if (!o.wilayah.some((w) => w.id === extra.lokasi_upt_id)) {
      return forbidden("Lokasi tersebut bukan wilayah kerja Bapas Anda.");
    }
    uptId = extra.lokasi_upt_id;
  }
  if (!uptId) return forbidden();

  const asesorUsername = extra.asesor || session.username;
  const check = await validateSigners(uptId, {
    wali: extra.wali, nakes: extra.nakes,
    asesor: asesorUsername === session.username && uptId === session.upt_id ? null : asesorUsername,
  });
  if (!check.ok) return { success: false, message: check.message };
  // Asesor yang bukan dari UPT pemilik (mis. dari Bapas): catat UPT asalnya.
  const asesorUptId = uptId !== session.upt_id && asesorUsername === session.username
    ? session.upt_id
    : check.asesorUptId;

  const id = nowJakartaTimestamp();
  const noRegister = extractNoRegister(payload);

  const { error } = await supabase.from("hasil_asesmen").insert({
    id,
    no_register: noRegister,
    payload,
    upt_id: uptId, // selalu divalidasi dari sesi, bukan dipercaya dari client
    asesor_upt_id: asesorUptId,
    asesor_username: asesorUsername,
    wali_username: extra.wali || null,
    nakes_username: extra.nakes || null,
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
    .select("id, payload, upt_id, asesor_username, wali_username, nakes_username, updated_at, upt:upt_id(nama, kanwil:kanwil_id(nama))")
    .order("created_at", { ascending: false });
  if (uptIds !== null) {
    // Termasuk data yang diasesmen oleh UPT asal asesor (mis. Bapas).
    query = query.or(`upt_id.in.(${uptIds.join(",")}),asesor_upt_id.in.(${uptIds.join(",")})`);
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
    row.asesor_username ?? "",
    row.upt_id ?? "",
  ]);
  return { success: true, data: records };
}

async function updateDataAsesmen(session: SessionPayload, idNoreg: string, payload: unknown[], extra: SaveExtra) {
  if (session.tingkat !== "UPT") {
    return forbidden("Hanya user tingkat UPT yang dapat mengubah data asesmen.");
  }
  if ((await lockStatus(session)).locked) return forbidden("Aplikasi sedang dikunci.");
  const target = String(idNoreg).trim();
  const newNoRegister = extractNoRegister(payload);

  const { data: existing, error: findError } = await supabase
    .from("hasil_asesmen")
    .select("id, upt_id, asesor_upt_id, asesor_username, wali_username, nakes_username")
    .eq("no_register", target)
    .maybeSingle();

  if (findError || !existing) {
    return { success: false, message: "Gagal update. No. Register tidak ditemukan di database." };
  }
  if (!canEditRecord(session, existing)) {
    return forbidden("Data ini bukan milik UPT Anda.");
  }

  // Wali, nakes, dan asesor saling dapat mengedit; hanya validasi penandatangan yang berubah.
  const wali = extra.wali || null;
  const nakes = extra.nakes || null;
  const asesor = extra.asesor || existing.asesor_username || null;
  const check = await validateSigners(existing.upt_id, {
    wali: wali !== existing.wali_username ? wali : null,
    nakes: nakes !== existing.nakes_username ? nakes : null,
    asesor: asesor !== existing.asesor_username ? asesor : null,
  });
  if (!check.ok) return { success: false, message: check.message };
  const changes: Record<string, unknown> = {
    no_register: newNoRegister, payload, wali_username: wali, nakes_username: nakes, asesor_username: asesor,
  };
  if (asesor !== existing.asesor_username) changes.asesor_upt_id = check.asesorUptId;

  const { error: updateError } = await supabase
    .from("hasil_asesmen")
    .update(changes)
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
    .select("id, upt_id, asesor_upt_id")
    .eq("no_register", target)
    .maybeSingle();

  if (findError || !existing) {
    return { success: false, message: "Gagal hapus. No. Register tidak ditemukan." };
  }
  if (!canEditRecord(session, existing)) {
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

const MAX_PHOTO_LENGTH = 200_000;

async function getMyPhoto(session: SessionPayload) {
  const { data, error } = await supabase
    .from("users")
    .select("foto")
    .eq("username", session.username)
    .maybeSingle();
  if (error) return { success: false, message: error.message };
  return { success: true, image: data?.foto ?? null };
}

async function saveMyPhoto(session: SessionPayload, image: unknown) {
  if (image !== null && image !== undefined && image !== "") {
    if (typeof image !== "string" || !/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(image)) {
      return { success: false, message: "Format foto harus PNG atau JPEG." };
    }
    if (image.length > MAX_PHOTO_LENGTH) {
      return { success: false, message: "Ukuran foto terlalu besar." };
    }
  }
  const { error } = await supabase
    .from("users")
    .update({ foto: image || null })
    .eq("username", session.username);
  if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
  return { success: true, message: image ? "Foto berhasil disimpan." : "Foto dihapus." };
}

// Daftar calon penandatangan untuk UPT lokasi WBP (default: UPT pemanggil).
// wali & nakes = pegawai UPT lokasi; asesor = pegawai UPT lokasi + Bapas yang mencakup wilayahnya.
async function listPenandatangan(session: SessionPayload, lokasiUptId?: string) {
  if (session.tingkat !== "UPT" || !session.upt_id) return forbidden();
  let uptId = session.upt_id;
  if (lokasiUptId && lokasiUptId !== session.upt_id) {
    const o = await lokasiAsesmenOptions(session);
    if (!o.wilayah.some((w) => w.id === lokasiUptId)) {
      // Boleh juga untuk data yang sudah ada milik UPT lain yang melibatkan UPT pemanggil.
      const bapas = (await coveringBapas(lokasiUptId)).map((b) => b.id);
      if (!bapas.includes(session.upt_id)) return forbidden();
    }
    uptId = lokasiUptId;
  }
  const uptIds = [uptId, ...(await coveringBapas(uptId)).map((b) => b.id)];
  const { data, error } = await supabase
    .from("users")
    .select("username, nama, peran, status_penandatangan, upt_id, tanda_tangan, upt:upt_id(nama)")
    .in("upt_id", uptIds)
    .order("nama");
  if (error) return { success: false, message: error.message };
  // deno-lint-ignore no-explicit-any
  const rows = (data ?? []).map((u: any) => ({
    username: u.username,
    nama: u.nama,
    peran: u.peran,
    status: u.status_penandatangan ?? [],
    upt_id: u.upt_id,
    upt_nama: u.upt?.nama ?? "",
    has_ttd: !!u.tanda_tangan,
  }));
  return { success: true, data: rows.filter((u) => u.upt_id === uptId), asesor: rows };
}

// Data pengesahan (nama + gambar tanda tangan) untuk satu asesmen, dengan
// pembatasan lingkup yang sama seperti readDataAsesmen.
async function getPengesahan(session: SessionPayload, idNoreg: string) {
  const { data: rec, error } = await supabase
    .from("hasil_asesmen")
    .select("upt_id, asesor_upt_id, payload, asesor_username, wali_username, nakes_username")
    .eq("no_register", String(idNoreg).trim())
    .maybeSingle();
  if (error || !rec) return { success: false, message: "Data asesmen tidak ditemukan." };

  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && !uptIds.includes(rec.upt_id) && !(rec.asesor_upt_id && uptIds.includes(rec.asesor_upt_id))) {
    return forbidden();
  }

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
      .in("upt_id", [rec.upt_id, rec.asesor_upt_id].filter(Boolean))
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
        .or(`upt_id.in.(${uptIds.join(",")}),asesor_upt_id.in.(${uptIds.join(",")})`)
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
// Wilayah kerja Bapas -- referensi Lapas/Rutan/LPKA yang dicakup tiap Bapas.
//   DITJEN: semua Bapas. KANWIL: Bapas di provinsinya. Kepala Bapas: Bapas sendiri.
//   User UPT lain hanya melihat (Bapas sendiri / Bapas yang mencakup UPT-nya).
// ---------------------------------------------------------------------------
function canManageBapas(session: SessionPayload, bapas: UptRow): boolean {
  if (bapas.jenis !== JENIS_BAPAS) return false;
  if (session.tingkat === "DITJEN") return true;
  if (session.tingkat === "KANWIL") return bapas.kanwil_id === session.kanwil_id;
  return isKepalaBapas(session) && session.upt_id === bapas.id;
}

async function listWilayahKerja(session: SessionPayload) {
  const { data: all, error } = await supabase
    .from("upt")
    .select("id, nama, jenis, kanwil_id, kanwil:kanwil_id(nama)")
    .order("nama");
  if (error) return { success: false, message: error.message };
  // deno-lint-ignore no-explicit-any
  const upts = (all ?? []) as any[];

  const { data: rows } = await supabase.from("bapas_wilayah_kerja").select("bapas_id, upt_id");
  const byBapas = new Map<string, string[]>();
  for (const r of rows ?? []) {
    const arr = byBapas.get(r.bapas_id) ?? [];
    arr.push(r.upt_id);
    byBapas.set(r.bapas_id, arr);
  }

  const own = session.tingkat === "UPT" ? upts.find((u) => u.id === session.upt_id) : null;
  const inScope = (u: { id: string; kanwil_id: string }) => {
    if (session.tingkat === "DITJEN") return true;
    if (session.tingkat === "KANWIL") return u.kanwil_id === session.kanwil_id;
    return !!own && u.kanwil_id === own.kanwil_id;
  };
  const uptById = new Map(upts.map((u) => [u.id as string, u]));

  const bapasList = upts
    .filter((u) => u.jenis === JENIS_BAPAS && inScope(u))
    .filter((u) => {
      if (session.tingkat !== "UPT") return true;
      // User UPT: Bapas sendiri atau Bapas yang mencakup UPT-nya.
      return u.id === session.upt_id || (byBapas.get(u.id) ?? []).includes(session.upt_id as string);
    })
    .map((u) => ({
      id: u.id,
      nama: u.nama,
      kanwil_id: u.kanwil_id,
      kanwil_nama: u.kanwil?.nama ?? "",
      can_manage: canManageBapas(session, u),
      wilayah: (byBapas.get(u.id) ?? [])
        .map((id) => uptById.get(id))
        .filter(Boolean)
        // deno-lint-ignore no-explicit-any
        .map((w: any) => ({ id: w.id, nama: w.nama, jenis: w.jenis })),
    }));

  const kandidat = upts
    .filter((u) => u.jenis !== JENIS_BAPAS && inScope(u))
    .map((u) => ({ id: u.id, nama: u.nama, jenis: u.jenis, kanwil_id: u.kanwil_id }));

  return { success: true, bapas: bapasList, kandidat };
}

async function setWilayahKerja(session: SessionPayload, bapasId: string, uptIds: unknown) {
  const bapas = await getUptRow(bapasId);
  if (!bapas || bapas.jenis !== JENIS_BAPAS) return { success: false, message: "Bapas tidak ditemukan." };
  if (!canManageBapas(session, bapas)) return forbidden("Anda tidak berwenang mengubah wilayah kerja Bapas ini.");
  if (!Array.isArray(uptIds)) return { success: false, message: "Daftar UPT tidak valid." };

  const wanted = [...new Set(uptIds.map(String))];
  if (wanted.length > 0) {
    const { data } = await supabase.from("upt").select("id, jenis, kanwil_id").in("id", wanted);
    const found = data ?? [];
    if (found.length !== wanted.length) return { success: false, message: "Ada UPT yang tidak ditemukan." };
    if (found.some((u) => u.jenis === JENIS_BAPAS)) {
      return { success: false, message: "Wilayah kerja hanya berisi Lapas/Rutan/LPKA." };
    }
    if (found.some((u) => u.kanwil_id !== bapas.kanwil_id)) {
      return { success: false, message: "UPT harus berada dalam provinsi (Kanwil) yang sama dengan Bapas." };
    }
  }

  const { data: cur } = await supabase.from("bapas_wilayah_kerja").select("upt_id").eq("bapas_id", bapasId);
  const current = (cur ?? []).map((r) => r.upt_id as string);
  const toAdd = wanted.filter((id) => !current.includes(id));
  const toRemove = current.filter((id) => !wanted.includes(id));

  if (toAdd.length > 0) {
    const { error } = await supabase
      .from("bapas_wilayah_kerja")
      .insert(toAdd.map((upt_id) => ({ bapas_id: bapasId, upt_id })));
    if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
  }
  if (toRemove.length > 0) {
    const { error } = await supabase
      .from("bapas_wilayah_kerja")
      .delete()
      .eq("bapas_id", bapasId)
      .in("upt_id", toRemove);
    if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
  }
  return { success: true, message: "Wilayah kerja Bapas berhasil disimpan." };
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

  const selectCols = "username, nama, peran, status_penandatangan, tingkat, upt_id, kanwil_id, upt:upt_id(nama), kanwil:kanwil_id(nama)";

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

const STATUS_PENANDATANGAN = ["asesor", "wali", "nakes"];

// Mengembalikan daftar status yang valid & unik, atau null bila ada nilai tak dikenal.
function normalizeStatus(v: unknown): string[] | null {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return null;
  const out = [...new Set(v.map(String))];
  return out.every((x) => STATUS_PENANDATANGAN.includes(x)) ? out : null;
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
  const status = normalizeStatus(payload.status_penandatangan);
  if (status === null) return { success: false, message: "Status penandatangan tidak valid." };

  const { error } = await supabase.from("users").insert({
    username,
    password_hash: hashSync(password),
    nama,
    peran: peran ?? "",
    tingkat,
    upt_id: tingkat === "UPT" ? upt_id : null,
    kanwil_id: tingkat === "KANWIL" ? kanwil_id : null,
    status_penandatangan: status,
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
  if (payload.status_penandatangan !== undefined) {
    const status = normalizeStatus(payload.status_penandatangan);
    if (status === null) return { success: false, message: "Status penandatangan tidak valid." };
    update.status_penandatangan = status;
  }

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

// ---------------------------------------------------------------------------
// Modul Registrasi: database klien Bapas
//   - UPT: kelola (tambah/ubah/hapus) klien milik UPT-nya sendiri.
//   - Kanwil/Ditjen: hanya melihat sesuai lingkup (tanpa mengubah).
// ---------------------------------------------------------------------------
const KLIEN_FIELDS = [
  "no_register", "nik", "nama", "tanggal_lahir", "agama", "kewarganegaraan",
  "pendidikan_terakhir", "pekerjaan", "status_pernikahan", "alamat", "no_hp",
  "nama_penjamin", "no_hp_penjamin", "perkara", "pasal", "lama_pidana", "asal_instansi",
  "jenis_kelamin", "pk", "jenis_integrasi", "kategori", "tanggal_penerimaan", "tanggal_ekspirasi",
  "status_pembimbingan", "daerah",
] as const;
const KLIEN_LIST_COLS = "id, upt_id, " + KLIEN_FIELDS.join(", ") + ", upt:upt_id(nama)";
const MAX_KLIEN_FOTO_LENGTH = 200_000;

function canManageKlien(session: SessionPayload): boolean {
  return session.tingkat === "UPT" && !!session.upt_id;
}

async function klienInScope(session: SessionPayload, id: string) {
  const { data } = await supabase.from("klien").select("id, upt_id").eq("id", id).maybeSingle();
  if (!data) return null;
  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && !uptIds.includes(data.upt_id as string)) return null;
  return data;
}

// Validasi & normalisasi payload. Mengembalikan pesan error atau record bersih.
function cleanKlien(payload: Record<string, unknown>, partialFoto: boolean) {
  const rec: Record<string, unknown> = {};
  for (const f of KLIEN_FIELDS) {
    const v = payload?.[f];
    const t = v === null || v === undefined ? "" : String(v).trim();
    if (t.length > 500) return { error: `Isian "${f}" terlalu panjang.` };
    rec[f] = t === "" ? null : t;
  }
  if (!rec.no_register) return { error: "No Register Klien wajib diisi." };
  if (!rec.nama) return { error: "Nama lengkap wajib diisi." };
  if (rec.nik && !/^\d{16}$/.test(rec.nik as string)) return { error: "NIK harus 16 digit angka." };
  if (rec.tanggal_lahir && !/^\d{4}-\d{2}-\d{2}$/.test(rec.tanggal_lahir as string)) {
    return { error: "Format tanggal lahir tidak valid." };
  }
  for (const f of ["tanggal_penerimaan", "tanggal_ekspirasi"]) {
    if (rec[f] && !/^\d{4}-\d{2}-\d{2}$/.test(rec[f] as string)) return { error: `Format ${f} tidak valid.` };
  }
  const foto = payload?.foto;
  if (foto !== undefined) {
    if (foto === null || foto === "") rec.foto = null;
    else if (
      typeof foto !== "string" || !/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(foto) ||
      foto.length > MAX_KLIEN_FOTO_LENGTH
    ) return { error: "Foto harus PNG/JPEG dan berukuran kecil." };
    else rec.foto = foto;
  } else if (!partialFoto) {
    rec.foto = null;
  }
  return { rec };
}

async function listKlien(session: SessionPayload) {
  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && uptIds.length === 0) return { success: true, data: [], can_manage: false };
  let q = supabase.from("klien").select(KLIEN_LIST_COLS).order("nama");
  if (uptIds !== null) q = q.in("upt_id", uptIds);
  const { data, error } = await q;
  if (error) return { success: false, message: error.message };
  return { success: true, data, can_manage: canManageKlien(session) };
}

async function getKlien(session: SessionPayload, id: string) {
  if (!(await klienInScope(session, id))) return forbidden("Data klien tidak ditemukan.");
  const { data, error } = await supabase
    .from("klien")
    .select(KLIEN_LIST_COLS + ", foto, created_at, updated_at")
    .eq("id", id)
    .maybeSingle();
  if (error || !data) return { success: false, message: error?.message ?? "Data klien tidak ditemukan." };
  return { success: true, data, can_manage: canManageKlien(session) };
}

async function createKlien(session: SessionPayload, payload: Record<string, unknown>) {
  if (!canManageKlien(session)) return forbidden("Hanya user UPT yang dapat menambah data klien.");
  const c = cleanKlien(payload, false);
  if (c.error) return { success: false, message: c.error };
  const { data, error } = await supabase
    .from("klien")
    .insert({ ...c.rec, upt_id: session.upt_id, created_by: session.username })
    .select("id")
    .single();
  if (error) {
    if (error.code === "23505") return { success: false, message: "No Register tersebut sudah terdaftar di UPT Anda." };
    return { success: false, message: "Gagal menyimpan: " + error.message };
  }
  return { success: true, id: data.id, message: "Data klien berhasil ditambahkan." };
}

async function updateKlien(session: SessionPayload, id: string, payload: Record<string, unknown>) {
  if (!canManageKlien(session)) return forbidden("Hanya user UPT yang dapat mengubah data klien.");
  const rec0 = await klienInScope(session, id);
  if (!rec0 || rec0.upt_id !== session.upt_id) return forbidden("Data klien tidak ditemukan.");
  const c = cleanKlien(payload, true);
  if (c.error) return { success: false, message: c.error };
  const { error } = await supabase
    .from("klien")
    .update({ ...c.rec, updated_at: new Date().toISOString() })
    .eq("id", id);
  if (error) {
    if (error.code === "23505") return { success: false, message: "No Register tersebut sudah terdaftar di UPT Anda." };
    return { success: false, message: "Gagal menyimpan: " + error.message };
  }
  return { success: true, message: "Data klien berhasil diperbarui." };
}

async function deleteKlien(session: SessionPayload, id: string) {
  if (!canManageKlien(session)) return forbidden("Hanya user UPT yang dapat menghapus data klien.");
  const rec0 = await klienInScope(session, id);
  if (!rec0 || rec0.upt_id !== session.upt_id) return forbidden("Data klien tidak ditemukan.");
  const { error } = await supabase.from("klien").delete().eq("id", id);
  if (error) return { success: false, message: "Gagal menghapus: " + error.message };
  return { success: true, message: "Data klien dihapus." };
}

// ---------------------------------------------------------------------------
// Modul Pengawasan: pelacakan lokasi klien
//   - Presensi dikirim klien lewat halaman publik (tanpa login).
//   - Petugas melihat lokasi sesuai lingkup; hanya user UPT yang mengatur wilayah izin.
// ---------------------------------------------------------------------------
const MAX_PRESENSI_FOTO_LENGTH = 400_000;
const PRESENSI_COLS = "id, klien_id, waktu, latitude, longitude, baterai, pekerjaan, alamat_domisili, kendala";

function escLike(v: string) {
  return v.replace(/[\\%_]/g, (c) => "\\" + c);
}

async function cariKlienPublik(noRegister: unknown) {
  const nr = typeof noRegister === "string" ? noRegister.trim() : "";
  if (!nr || nr.length > 100) return [];
  const { data } = await supabase
    .from("klien")
    .select("id, upt_id, no_register, nama, wilayah_izin, upt:upt_id(nama)")
    .ilike("no_register", escLike(nr))
    .limit(10);
  return data ?? [];
}

async function publicCekKlien(noRegister: unknown) {
  const rows = await cariKlienPublik(noRegister);
  if (!rows.length) return { success: true, found: false };
  return {
    success: true,
    found: true,
    matches: rows.map((r: Record<string, unknown>) => ({
      upt_id: r.upt_id,
      upt: (r.upt as { nama?: string } | null)?.nama ?? "-",
      nama: r.nama,
      wilayah: r.wilayah_izin ?? "-",
    })),
  };
}

async function publicPresensi(body: Record<string, unknown>) {
  const rows = await cariKlienPublik(body.no_register);
  const cocok = body.upt_id ? rows.filter((r: Record<string, unknown>) => r.upt_id === body.upt_id) : rows;
  if (!cocok.length) return { success: false, message: "No Register klien tidak terdaftar." };
  if (cocok.length > 1) return { success: false, message: "No Register ada di lebih dari satu UPT, pilih UPT Anda." };
  const klien = cocok[0] as Record<string, unknown>;

  const lat = Number(body.latitude), lng = Number(body.longitude);
  if (!isFinite(lat) || !isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
    return { success: false, message: "Koordinat lokasi tidak valid." };
  }
  const foto = body.foto;
  if (
    typeof foto !== "string" || !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(foto) ||
    foto.length > MAX_PRESENSI_FOTO_LENGTH
  ) return { success: false, message: "Foto presensi wajib (JPEG) dan berukuran kecil." };
  const txt = (v: unknown) => (typeof v === "string" ? v.trim().slice(0, 500) : "") || null;
  const bat = Number(body.baterai);

  const { data: last } = await supabase
    .from("presensi_klien").select("waktu").eq("klien_id", klien.id).order("waktu", { ascending: false }).limit(1);
  if (last?.length && Date.now() - new Date(last[0].waktu as string).getTime() < 30_000) {
    return { success: false, message: "Presensi baru saja terkirim, coba lagi sebentar." };
  }

  const { error } = await supabase.from("presensi_klien").insert({
    klien_id: klien.id,
    latitude: lat,
    longitude: lng,
    baterai: isFinite(bat) && bat >= 0 && bat <= 100 ? Math.round(bat) : null,
    pekerjaan: txt(body.pekerjaan),
    alamat_domisili: txt(body.alamat_domisili),
    kendala: txt(body.kendala),
    foto,
  });
  if (error) return { success: false, message: "Gagal menyimpan presensi." };
  return { success: true, message: "Presensi berhasil terkirim.", nama: klien.nama };
}

async function listLokasiKlien(session: SessionPayload) {
  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && uptIds.length === 0) return { success: true, data: [], can_manage: false };
  let q = supabase
    .from("klien")
    .select("id, upt_id, no_register, nama, no_hp, alamat, daerah, wilayah_izin, lat_pusat, long_pusat, radius_km, upt:upt_id(nama)")
    .order("nama");
  if (uptIds !== null) q = q.in("upt_id", uptIds);
  const { data: klien, error } = await q;
  if (error) return { success: false, message: error.message };
  const ids = (klien ?? []).map((k: Record<string, unknown>) => k.id as string);
  const terbaru: Record<string, Record<string, unknown>> = {};
  for (let i = 0; i < ids.length; i += 200) {
    const { data: pres } = await supabase
      .from("presensi_klien")
      .select(PRESENSI_COLS)
      .in("klien_id", ids.slice(i, i + 200))
      .order("waktu", { ascending: false })
      .limit(5000);
    for (const p of pres ?? []) if (!terbaru[p.klien_id as string]) terbaru[p.klien_id as string] = p;
  }
  const data = (klien ?? []).map((k: Record<string, unknown>) => ({ ...k, terakhir: terbaru[k.id as string] ?? null }));
  return { success: true, data, can_manage: canManageKlien(session) };
}

async function listRiwayatPresensi(session: SessionPayload, klienId: string) {
  if (!(await klienInScope(session, klienId))) return forbidden("Data klien tidak ditemukan.");
  const { data, error } = await supabase
    .from("presensi_klien").select(PRESENSI_COLS).eq("klien_id", klienId).order("waktu", { ascending: false }).limit(100);
  if (error) return { success: false, message: error.message };
  return { success: true, data };
}

async function getFotoPresensi(session: SessionPayload, id: string) {
  const { data } = await supabase.from("presensi_klien").select("klien_id, foto").eq("id", id).maybeSingle();
  if (!data || !(await klienInScope(session, data.klien_id as string))) return forbidden("Data tidak ditemukan.");
  return { success: true, foto: data.foto };
}

async function saveWilayahKlien(session: SessionPayload, id: string, payload: Record<string, unknown>) {
  if (!canManageKlien(session)) return forbidden("Hanya user UPT yang dapat mengatur wilayah izin klien.");
  const rec0 = await klienInScope(session, id);
  if (!rec0 || rec0.upt_id !== session.upt_id) return forbidden("Data klien tidak ditemukan.");
  const num = (v: unknown) => (v === null || v === undefined || String(v).trim() === "" ? null : Number(v));
  const lat = num(payload?.lat_pusat), lng = num(payload?.long_pusat), rad = num(payload?.radius_km);
  if ([lat, lng, rad].some((n) => n !== null && !isFinite(n))) return { success: false, message: "Angka tidak valid." };
  if ((lat === null) !== (lng === null)) return { success: false, message: "Latitude dan longitude harus diisi bersamaan." };
  if (lat !== null && (Math.abs(lat) > 90 || Math.abs(lng as number) > 180)) return { success: false, message: "Koordinat tidak valid." };
  if (rad !== null && (rad <= 0 || rad > 5000)) return { success: false, message: "Radius harus antara 0 dan 5000 km." };
  const w = typeof payload?.wilayah_izin === "string" ? payload.wilayah_izin.trim().slice(0, 200) : "";
  const { error } = await supabase
    .from("klien")
    .update({ wilayah_izin: w || null, lat_pusat: lat, long_pusat: lng, radius_km: rad, updated_at: new Date().toISOString() })
    .eq("id", id);
  if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
  return { success: true, message: "Wilayah izin disimpan." };
}

// ---------------------------------------------------------------------------
// Modul Litmas: laporan Penelitian Kemasyarakatan + riwayat versi.
//   - UPT: kelola Litmas untuk klien UPT-nya. Kanwil/Ditjen: hanya melihat.
//   - Setiap simpan menambah satu baris litmas_history (snapshot lengkap).
// ---------------------------------------------------------------------------
const LITMAS_TEXT = ["no_reg_litmas", "tgl_laporan", "pendahuluan", "analisis", "kesimpulan", "rekomendasi"] as const;
const LITMAS_OBJ = ["header", "identitas", "riwayat", "komponen", "pejabat"] as const;
const LITMAS_LIST_COLS =
  "id, upt_id, klien_id, jenis_litmas, no_reg_litmas, tgl_laporan, versi, updated_by, updated_at, created_at, klien:klien_id(nama, no_register), upt:upt_id(nama)";

function cleanLitmas(payload: Record<string, unknown>) {
  const rec: Record<string, unknown> = {};
  const jenis = Number(payload?.jenis_litmas);
  if (!Number.isInteger(jenis) || jenis < 1 || jenis > 13) return { error: "Jenis Litmas tidak valid." };
  rec.jenis_litmas = jenis;
  for (const f of LITMAS_TEXT) {
    const v = payload?.[f];
    const t = v === null || v === undefined ? "" : String(v);
    if (t.length > 20000) return { error: `Isian "${f}" terlalu panjang.` };
    rec[f] = t.trim() === "" ? null : t;
  }
  for (const f of LITMAS_OBJ) {
    const v = payload?.[f];
    if (v === undefined || v === null) { rec[f] = {}; continue; }
    if (typeof v !== "object" || Array.isArray(v)) return { error: `Isian "${f}" tidak valid.` };
    const clean: Record<string, string> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (!/^[A-Za-z0-9_]{1,40}$/.test(k)) continue;
      const t = val === null || val === undefined ? "" : String(val);
      if (t.length > 20000) return { error: `Isian "${k}" terlalu panjang.` };
      clean[k] = t;
    }
    rec[f] = clean;
  }
  return { rec };
}

async function litmasInScope(session: SessionPayload, id: string) {
  const { data } = await supabase.from("litmas").select("*").eq("id", id).maybeSingle();
  if (!data) return null;
  const uptIds = await scopedUptIds(session);
  if (uptIds !== null && !uptIds.includes(data.upt_id as string)) return null;
  return data as Record<string, unknown>;
}

async function listLitmas(session: SessionPayload) {
  const uptIds = await scopedUptIds(session);
  const can_manage = canManageKlien(session);
  let konteks: Record<string, string> | null = null;
  if (can_manage) {
    const { data: u } = await supabase.from("upt").select("nama, kanwil:kanwil_id(nama)").eq("id", session.upt_id).maybeSingle();
    if (u) konteks = { upt_nama: u.nama as string, kanwil_nama: ((u.kanwil as unknown as { nama: string } | null)?.nama) ?? "" };
  }
  if (uptIds !== null && uptIds.length === 0) return { success: true, data: [], can_manage, konteks };
  let q = supabase.from("litmas").select(LITMAS_LIST_COLS).order("updated_at", { ascending: false });
  if (uptIds !== null) q = q.in("upt_id", uptIds);
  const { data, error } = await q;
  if (error) return { success: false, message: error.message };
  return { success: true, data, can_manage, konteks };
}

async function getLitmas(session: SessionPayload, id: string) {
  const rec = await litmasInScope(session, id);
  if (!rec) return forbidden("Data Litmas tidak ditemukan.");
  const { data: hist } = await supabase
    .from("litmas_history")
    .select("id, versi, aksi, oleh, waktu, snapshot")
    .eq("litmas_id", id)
    .order("versi", { ascending: false });
  return { success: true, data: rec, riwayat: hist ?? [], can_manage: canManageKlien(session) };
}

async function saveLitmas(session: SessionPayload, id: string | undefined, payload: Record<string, unknown>) {
  if (!canManageKlien(session)) return forbidden("Hanya user UPT yang dapat mengelola Litmas.");
  const c = cleanLitmas(payload);
  if (c.error) return { success: false, message: c.error };
  const rec = c.rec as Record<string, unknown>;
  const now = new Date().toISOString();
  let litmasId = id;
  let versi = 1;
  let aksi = "Dibuat";
  if (id) {
    const old = await litmasInScope(session, id);
    if (!old || old.upt_id !== session.upt_id) return forbidden("Data Litmas tidak ditemukan.");
    versi = (old.versi as number) + 1;
    aksi = "Diperbarui";
    const { error } = await supabase
      .from("litmas")
      .update({ ...rec, versi, updated_by: session.username, updated_at: now })
      .eq("id", id);
    if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
  } else {
    const kid = String(payload?.klien_id ?? "");
    const k = await klienInScope(session, kid);
    if (!k || k.upt_id !== session.upt_id) return { success: false, message: "Klien tidak ditemukan." };
    const { data, error } = await supabase
      .from("litmas")
      .insert({ ...rec, klien_id: kid, upt_id: session.upt_id, created_by: session.username, updated_by: session.username })
      .select("id")
      .single();
    if (error) return { success: false, message: "Gagal menyimpan: " + error.message };
    litmasId = data.id as string;
  }
  const { error: hErr } = await supabase.from("litmas_history").insert({
    litmas_id: litmasId, versi, aksi, oleh: session.nama || session.username, waktu: now,
    snapshot: { ...rec },
  });
  if (hErr) return { success: false, message: "Litmas tersimpan, tetapi riwayat gagal dicatat: " + hErr.message };
  return { success: true, id: litmasId, versi, message: id ? "Litmas diperbarui (versi " + versi + ")." : "Litmas berhasil disimpan." };
}

async function deleteLitmas(session: SessionPayload, id: string) {
  if (!canManageKlien(session)) return forbidden("Hanya user UPT yang dapat menghapus Litmas.");
  const rec = await litmasInScope(session, id);
  if (!rec || rec.upt_id !== session.upt_id) return forbidden("Data Litmas tidak ditemukan.");
  const { error } = await supabase.from("litmas").delete().eq("id", id);
  if (error) return { success: false, message: "Gagal menghapus: " + error.message };
  return { success: true, message: "Litmas dihapus." };
}
