# Panduan Migrasi Backend: Google Apps Script -> Supabase

Dokumen ini menjelaskan cara memindahkan backend aplikasi dari Google Apps
Script + Google Sheets ke **Supabase** (Postgres + Edge Functions), dengan
kode backend disimpan di repo ini (`supabase/`).

## Arsitektur baru

```
index.html  --POST-->  Supabase Edge Function "api"  --service_role-->  Postgres (Supabase)
                        (supabase/functions/api/index.ts)                (tabel users, hasil_asesmen)
```

- Edge Function `api` menggantikan `doPost()` di `Code.gs`, dengan action
  yang sama persis: `login`, `save`, `read`, `update`, `delete`.
- Tabel Postgres dilindungi Row Level Security tanpa policy sama sekali,
  jadi **tidak bisa** diakses langsung lewat REST API publik (anon key).
  Semua akses wajib lewat Edge Function yang memakai `service_role` key
  di sisi server (tidak pernah dikirim ke browser).
- Password disimpan sebagai **hash bcrypt**, bukan teks polos seperti di
  Google Sheets sebelumnya.

## Peringatan keamanan penting

Di sheet "Users" saat ini, password = sama persis dengan username (NIP
pegawai). Ini **sangat tidak aman** karena NIP adalah data yang mudah
diketahui orang lain. Setelah migrasi, sangat disarankan:
1. Meminta setiap user mengganti password masing-masing.
2. Atau, siapkan password acak baru untuk tiap user saat proses import.

Migrasi ini TIDAK mengubah mekanisme tersebut secara otomatis (supaya
login tetap berfungsi seperti sebelumnya), hanya mengamankan penyimpanannya
(hash, bukan plaintext).

## Langkah 1 - Buat project Supabase

1. Daftar/login di https://supabase.com, buat **New project**.
2. Catat **Project URL** dan **Project Ref** (terlihat di Project Settings > API).
3. Catat juga **anon public key** (untuk kebutuhan lain di masa depan jika diperlukan).

## Langkah 2 - Install & login Supabase CLI (di komputer Anda)

```bash
npm install -g supabase
supabase login
```

## Langkah 3 - Hubungkan repo ke project Supabase

Dari root repo:

```bash
supabase link --project-ref <PROJECT_REF_ANDA>
```

Edit `supabase/config.toml`, ganti `GANTI_DENGAN_PROJECT_REF_ANDA` dengan
project ref Anda.

## Langkah 4 - Jalankan migrasi skema database

```bash
supabase db push
```

Ini membuat tabel `users` dan `hasil_asesmen` sesuai
`supabase/migrations/0001_init.sql`.

## Langkah 5 - Deploy Edge Function

```bash
supabase functions deploy api --no-verify-jwt
```

Setelah sukses, CLI menampilkan Function URL, formatnya kurang lebih:
`https://<project-ref>.functions.supabase.co/api`

## Langkah 6 - Export data lama dari Google Sheets

Di Google Sheets:
1. Buka sheet **Users** -> File > Download > Comma Separated Values (.csv)
   -> simpan sebagai `supabase/import/data/users.csv`
2. Buka sheet **Hasil_Asesmen** -> File > Download > Comma Separated Values
   (.csv) -> simpan sebagai `supabase/import/data/hasil_asesmen.csv`

Folder `supabase/import/data/` sudah di-`.gitignore`, file CSV ini **tidak**
akan ter-commit ke GitHub (karena berisi data pribadi).

## Langkah 7 - Jalankan skrip import

```bash
cd supabase/import
npm install
export SUPABASE_URL="https://<project-ref>.supabase.co"
export SUPABASE_SERVICE_ROLE_KEY="<service_role_key_dari_Project_Settings_API>"
npm run import
```

Skrip ini akan meng-hash semua password dengan bcrypt sebelum disimpan ke
Supabase (lihat `supabase/import/import-data.mjs`).

## Langkah 8 - Update frontend

Di `index.html`, ganti baris:

```js
const API_URL = "https://xxxxxxxxxxxx.functions.supabase.co/api";
```

dengan Function URL dari Langkah 5.

## Langkah 9 - Uji coba

1. Jalankan aplikasi (`python3 -m http.server` atau sejenisnya).
2. Coba login dengan salah satu akun yang sudah diimpor.
3. Coba simpan, edit, hapus data asesmen, dan cek tombol
   Buka/Kunci Aplikasi (muncul untuk user dengan peran "Kepala Bapas").

## Rollback

Selama Apps Script lama belum dimatikan, Anda bisa kembalikan
`API_URL` ke URL `script.google.com/.../exec` yang lama kapan saja sebagai
jalur mundur, tanpa kehilangan data (karena proses import tidak menghapus
data asli di Google Sheets).

## Struktur organisasi berjenjang nasional (UPT / Kanwil / Ditjen)

Sejak migrasi `0002_struktur_wilayah.sql`, aplikasi mendukung 3 level
organisasi untuk penggunaan skala nasional:

- **UPT** (kabupaten/kota) — Balai Pemasyarakatan (Bapas), Lembaga
  Pemasyarakatan (Lapas), Rumah Tahanan Negara (Rutan), atau Lembaga
  Pembinaan Khusus Anak (LPKA). Level ini adalah pengguna asesmen
  sehari-hari (sama persis dengan pengalaman aplikasi sebelumnya).
- **KANWIL** (provinsi) — memantau seluruh data asesmen & UPT dalam satu
  provinsi, dan dapat mengubah (bukan membuat/menghapus) profil UPT di
  wilayahnya.
- **DITJEN** (nasional) — memantau seluruh data secara nasional, dan satu
  -satunya level yang dapat membuat/menghapus Kanwil & UPT.

### Tabel baru

- `kanwil` — profil Kantor Wilayah (nama, provinsi, kepala, alamat).
- `upt` — profil Unit Pelaksana Teknis, terhubung ke `kanwil` lewat
  `kanwil_id`.
- `ditjen_profile` — profil Ditjen, tabel singleton (hanya 1 baris, `id=1`).
- `users.tingkat` / `users.upt_id` / `users.kanwil_id` — menentukan level
  & unit organisasi setiap user, terpisah dari `peran` (jabatan, mis.
  "Kepala Bapas") yang sudah ada sebelumnya.
- `hasil_asesmen.upt_id` — UPT **milik asesor** yang menginput data
  (diisi otomatis dari sesi login, bukan dari form), dipakai untuk
  pemantauan berjenjang. Ini berbeda dari kolom bebas "UPT/Kanwil" di
  dalam form yang menjelaskan Lapas/Rutan tempat narapidana ditahan.

### Sesi & otorisasi

Edge Function sekarang mengeluarkan **token sesi** (HMAC-SHA256,
berlaku 12 jam) saat `login`, berisi identitas & lingkup organisasi
pemanggil. Semua action selain `login` wajib menyertakan `token` ini;
server memverifikasi token dan membatasi data/aksi berdasarkan lingkup
organisasi yang tertanam di dalamnya (tidak bisa dipalsukan dari client).

Secret `APP_SESSION_SECRET` untuk menandatangani token di-set lewat:

```bash
supabase secrets set APP_SESSION_SECRET=<nilai_acak_panjang>
```

### Action baru di Edge Function

`listKanwil`, `createKanwil`, `updateKanwil`, `deleteKanwil`,
`listUpt`, `createUpt`, `updateUpt`, `deleteUpt`,
`getDitjenProfile`, `updateDitjenProfile`,
`listUsers`, `createUser`, `updateUser`, `deleteUser`,
`changePassword`.

### Tanda tangan pengesahan (migrasi `0003_tanda_tangan.sql`)

Setiap user dapat mengunggah gambar tanda tangan (tombol "Tanda Tangan
Saya"). Pada form asesmen, asesor memilih Wali Pemasyarakatan dan Tenaga
Kesehatan dari user di UPT-nya. Saat cetak PDF, blok pengesahan menampilkan
tiga tanda tangan di atas nama masing-masing. Action: `getMySignature`,
`saveMySignature`, `listPenandatangan`, `getPengesahan`. Kolom baru:
`users.tanda_tangan`, `hasil_asesmen.asesor_username/wali_username/nakes_username`.
Baris `read` kini memiliki 110 kolom (`[108]` wali, `[109]` nakes).
Data lama: asesor dicocokkan lewat nama; wali/nakes kosong sampai data diedit.

### UI baru

User tingkat KANWIL/DITJEN mendapat tab tambahan (Kelola Wilayah -
Ditjen saja, Kelola UPT, Kelola User, Profil Ditjen - Ditjen saja) serta
melihat kolom "UPT Asesor"/"Kanwil" tambahan pada dashboard "Data Asesmen"
(berfungsi sebagai dashboard pemantauan berjenjang). **User tingkat UPT
tidak mendapat perubahan tampilan apapun.**

