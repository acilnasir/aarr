#!/usr/bin/env node
// Impor user (PK) satu Bapas dari CSV. Username = NIP, password awal = NIP.
// CSV (header): nama,nip,jabatan  -> simpan di supabase/import/data/ (di-.gitignore).
//
// Pakai:
//   export SUPABASE_URL="https://xxxx.supabase.co"
//   export SUPABASE_SERVICE_ROLE_KEY="xxxx"   (Service Role key)
//   node import-users-bapas.mjs data/baubau.csv "Balai Pemasyarakatan Kelas II Baubau" "Sulawesi Tenggara" [--dry]
//
// UPT & Kanwil dibuat bila belum ada. User yang sudah ada (username sama) dilewati.

import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";
import { parse } from "csv-parse/sync";
import { readFileSync } from "node:fs";

const [file, uptNama, provinsi] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const dry = process.argv.includes("--dry");
if (!file || !uptNama || !provinsi) {
  console.error('Pakai: node import-users-bapas.mjs <file.csv> "<nama UPT>" "<provinsi kanwil>" [--dry]');
  process.exit(1);
}
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
if (!dry && (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)) {
  console.error("Set SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY terlebih dahulu.");
  process.exit(1);
}

const rows = parse(readFileSync(file, "utf8"), { columns: true, skip_empty_lines: true, trim: true, bom: true })
  .map((r) => ({ nama: r.nama, nip: String(r.nip).replace(/\D/g, ""), jabatan: r.jabatan }))
  .filter((r) => r.nama && r.nip);
const bad = rows.filter((r) => r.nip.length !== 18);
if (bad.length) {
  console.error("NIP tidak 18 digit (cek format teks di Excel):\n" + bad.map((r) => `  ${r.nama}: ${r.nip}`).join("\n"));
  process.exit(1);
}
if (new Set(rows.map((r) => r.nip)).size !== rows.length) {
  console.error("Ada NIP ganda di file.");
  process.exit(1);
}
console.log(`${rows.length} user siap diimpor ke "${uptNama}" (kanwil ${provinsi}).`);
if (dry) process.exit(0);

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const must = (r) => { if (r.error) { console.error(r.error.message); process.exit(1); } return r.data; };

let kanwil = must(await sb.from("kanwil").select("id").eq("provinsi", provinsi).maybeSingle());
if (!kanwil) {
  kanwil = must(await sb.from("kanwil").insert({ nama: `Kantor Wilayah ${provinsi}`, provinsi }).select("id").single());
  console.log("Kanwil dibuat.");
}
let upt = must(await sb.from("upt").select("id").eq("nama", uptNama).eq("kanwil_id", kanwil.id).maybeSingle());
if (!upt) {
  upt = must(await sb.from("upt").insert({ kanwil_id: kanwil.id, nama: uptNama, jenis: "Balai Pemasyarakatan" }).select("id").single());
  console.log("UPT dibuat.");
}

const existing = new Set(must(await sb.from("users").select("username").in("username", rows.map((r) => r.nip))).map((u) => u.username));
const baru = rows.filter((r) => !existing.has(r.nip));
const payload = baru.map((r) => ({
  username: r.nip,
  password_hash: bcrypt.hashSync(r.nip, 10),
  nama: r.nama,
  peran: r.jabatan,
  tingkat: "UPT",
  upt_id: upt.id,
  kanwil_id: null,
  status_penandatangan: ["asesor"],
}));
if (payload.length) must(await sb.from("users").insert(payload));
console.log(`Selesai: ${payload.length} ditambahkan, ${existing.size} dilewati (sudah ada).`);
