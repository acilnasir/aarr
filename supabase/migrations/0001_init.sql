-- Skema database Aplikasi Asesmen Narapidana (migrasi dari Google Sheets)
-- Jalankan dengan: supabase db push

-- =========================================================================
-- TABEL USERS (pengganti sheet "Users")
-- =========================================================================
create table if not exists public.users (
  username      text primary key,
  password_hash text not null,   -- hash bcrypt, BUKAN password polos
  nama          text not null,
  peran         text not null,   -- contoh: "Kepala Bapas", "PK Madya", dst.
  upt           text,
  created_at    timestamptz not null default now()
);

comment on table public.users is 'Data akun login asesor, pengganti sheet Users pada Google Sheets.';
comment on column public.users.peran is 'Jabatan/peran user. Nilai "Kepala Bapas" dipakai untuk menampilkan tombol buka/kunci aplikasi.';

-- =========================================================================
-- TABEL HASIL_ASESMEN (pengganti sheet "Hasil_Asesmen")
-- =========================================================================
-- "payload" menyimpan seluruh kolom formulir asesmen (M0-M4) sebagai array
-- JSON terurut, identik dengan urutan kolom pada spreadsheet lama, supaya
-- logika frontend (index.html) yang mengakses data secara positional
-- (row[1], row[2], dst.) tidak perlu diubah sama sekali.
create table if not exists public.hasil_asesmen (
  id          text primary key,        -- timestamp "yyyy-MM-dd HH:mm:ss" (format sama seperti Apps Script lama)
  no_register text not null unique,    -- No. Register narapidana, dipakai sebagai kunci update/delete
  payload     jsonb not null,          -- array lengkap data form (asesor, nama, upt, ...)
  created_at  timestamptz not null default now()
);

comment on table public.hasil_asesmen is 'Data hasil asesmen IKP-R, pengganti sheet Hasil_Asesmen pada Google Sheets.';

create index if not exists idx_hasil_asesmen_created_at on public.hasil_asesmen (created_at desc);

-- =========================================================================
-- ROW LEVEL SECURITY
-- RLS diaktifkan TANPA policy sama sekali, artinya tabel ini TIDAK BISA
-- diakses langsung lewat REST API publik (anon key). Semua akses hanya
-- lewat Edge Function "api" yang memakai service_role key di sisi server.
-- =========================================================================
alter table public.users enable row level security;
alter table public.hasil_asesmen enable row level security;
