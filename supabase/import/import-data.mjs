#!/usr/bin/env node
// Skrip migrasi data dari Google Sheets (CSV) ke Supabase.
// HANYA dijalankan secara LOKAL oleh Anda sendiri. Jangan commit file CSV
// hasil export (sudah di-.gitignore lewat folder supabase/import/data/).
//
// Cara pakai:
//   1. npm install @supabase/supabase-js bcryptjs csv-parse
//   2. Dari Google Sheets: File > Download > Comma Separated Values (.csv)
//      untuk SETIAP sheet (Users, Hasil_Asesmen), simpan sebagai:
//        supabase/import/data/users.csv
//        supabase/import/data/hasil_asesmen.csv
//   3. Set environment variable:
//        export SUPABASE_URL="https://xxxx.supabase.co"
//        export SUPABASE_SERVICE_ROLE_KEY="xxxx"   (Service Role key, BUKAN anon key)
//   4. node supabase/import/import-data.mjs

import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";
import { parse } from "csv-parse/sync";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "data");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error("Set SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY terlebih dahulu.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

function loadCsv(filename) {
  const filePath = path.join(DATA_DIR, filename);
  if (!existsSync(filePath)) {
    console.error(`File tidak ditemukan: ${filePath}`);
    console.error("Pastikan Anda sudah export CSV dari Google Sheets ke folder supabase/import/data/");
    process.exit(1);
  }
  const content = readFileSync(filePath, "utf8");
  return parse(content, { columns: false, skip_empty_lines: true });
}

async function importUsers() {
  const rows = loadCsv("users.csv");
  // Baris 0 = header ("Username", "Password", "Nama Lengkap", "Peran / Jabatan", "UPT / Unit Kerja")
  const users = [];
  for (let i = 1; i < rows.length; i++) {
    const [username, password, nama, peran, upt] = rows[i];
    if (!username) continue;
    const password_hash = await bcrypt.hash(String(password), 10);
    users.push({ username: String(username).trim(), password_hash, nama, peran, upt });
  }

  if (users.length === 0) {
    console.log("Tidak ada data user untuk diimpor.");
    return;
  }

  const { error } = await supabase.from("users").upsert(users, { onConflict: "username" });
  if (error) throw error;
  console.log(`Berhasil impor ${users.length} user.`);
}

async function importHasilAsesmen() {
  const rows = loadCsv("hasil_asesmen.csv");
  // Baris 0 = header. Kolom 0 = Timestamp, kolom 3 = No. Register, sisanya = payload form.
  const records = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const id = row[0];
    if (!id) continue;
    const payload = row.slice(1); // seluruh kolom setelah Timestamp
    const noRegister = String(payload[2] ?? "").trim(); // No. Register = payload index 2
    records.push({ id, no_register: noRegister, payload });
  }

  if (records.length === 0) {
    console.log("Tidak ada data asesmen untuk diimpor.");
    return;
  }

  const { error } = await supabase.from("hasil_asesmen").upsert(records, { onConflict: "id" });
  if (error) throw error;
  console.log(`Berhasil impor ${records.length} data asesmen.`);
}

try {
  await importUsers();
  await importHasilAsesmen();
  console.log("Selesai.");
} catch (err) {
  console.error("Gagal impor:", err);
  process.exit(1);
}
