// Supabase Edge Function: "api"
// Pengganti Code.gs (Google Apps Script) yang sebelumnya berjalan di Google Sheets.
// Mendukung action yang sama persis: login, save, read, update, delete.
//
// Deploy: supabase functions deploy api --no-verify-jwt
//
// Env vars SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY otomatis tersedia di
// runtime Edge Function Supabase, tidak perlu di-set manual.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { compare } from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Service role key -> bypass RLS, hanya dipakai di server (aman, tidak pernah dikirim ke browser).
const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS_HEADERS });
  }

  try {
    const body = await req.json();
    const action = body.action;
    let result: Record<string, unknown>;

    switch (action) {
      case "login":
        result = await checkLogin(body.username, body.password);
        break;
      case "save":
        result = await saveDataAsesmen(body.payload);
        break;
      case "read":
        result = await readDataAsesmen();
        break;
      case "update":
        result = await updateDataAsesmen(body.id, body.payload);
        break;
      case "delete":
        result = await deleteDataAsesmen(body.id);
        break;
      default:
        result = { success: false, message: "Aksi tidak dikenal." };
    }

    return new Response(JSON.stringify(result), {
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(
      JSON.stringify({ success: false, message: String(error) }),
      { headers: { ...CORS_HEADERS, "Content-Type": "application/json" } },
    );
  }
});

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

async function checkLogin(username: string, password: string) {
  const { data, error } = await supabase
    .from("users")
    .select("username, password_hash, nama, peran")
    .eq("username", username)
    .maybeSingle();

  if (error || !data) {
    return { success: false, message: "Username/password salah!" };
  }

  const valid = await compare(password, data.password_hash);
  if (!valid) {
    return { success: false, message: "Username/password salah!" };
  }

  return {
    success: true,
    user: { username: data.username, nama: data.nama, peran: data.peran },
  };
}

// payload[2] = No. Register (lihat urutan field di submitData() pada index.html)
function extractNoRegister(payload: unknown[]): string {
  return String(payload[2] ?? "").trim();
}

async function saveDataAsesmen(payload: unknown[]) {
  const id = nowJakartaTimestamp();
  const noRegister = extractNoRegister(payload);

  const { error } = await supabase.from("hasil_asesmen").insert({
    id,
    no_register: noRegister,
    payload,
  });

  if (error) {
    return { success: false, message: "Gagal menyimpan: " + error.message };
  }
  return { success: true, message: "Data asesmen berhasil ditambahkan!" };
}

async function readDataAsesmen() {
  const { data, error } = await supabase
    .from("hasil_asesmen")
    .select("id, payload")
    .order("created_at", { ascending: false }); // data terbaru tampil di atas, sama seperti sebelumnya

  if (error) {
    return { success: false, message: "Gagal membaca data: " + error.message };
  }

  // Bentuk ulang menjadi array [id, ...payload] agar identik dengan format
  // lama dari Google Sheets, supaya frontend tidak perlu diubah.
  const records = (data ?? []).map((row) => [row.id, ...(row.payload as unknown[])]);
  return { success: true, data: records };
}

async function updateDataAsesmen(idNoreg: string, payload: unknown[]) {
  const target = String(idNoreg).trim();
  const newNoRegister = extractNoRegister(payload);

  const { data: existing, error: findError } = await supabase
    .from("hasil_asesmen")
    .select("id")
    .eq("no_register", target)
    .maybeSingle();

  if (findError || !existing) {
    return { success: false, message: "Gagal update. No. Register tidak ditemukan di database." };
  }

  const { error: updateError } = await supabase
    .from("hasil_asesmen")
    .update({ no_register: newNoRegister, payload })
    .eq("id", existing.id);

  if (updateError) {
    return { success: false, message: "Gagal update: " + updateError.message };
  }
  return { success: true, message: "Data asesmen berhasil diperbarui (ditimpa)!" };
}

async function deleteDataAsesmen(idNoreg: string) {
  const target = String(idNoreg).trim();

  const { data: existing, error: findError } = await supabase
    .from("hasil_asesmen")
    .select("id")
    .eq("no_register", target)
    .maybeSingle();

  if (findError || !existing) {
    return { success: false, message: "Gagal hapus. No. Register tidak ditemukan." };
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
