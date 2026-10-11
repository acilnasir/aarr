-- Struktur organisasi berjenjang nasional:
--   DITJEN (nasional) -> KANWIL (provinsi) -> UPT (kabupaten/kota)
-- Jalankan dengan: supabase db push

-- =========================================================================
-- TABEL KANWIL (Kantor Wilayah - tingkat provinsi)
-- =========================================================================
create table if not exists public.kanwil (
  id         uuid primary key default gen_random_uuid(),
  nama       text not null,
  provinsi   text not null,
  alamat     text,
  kepala     text,          -- nama Kepala Kantor Wilayah
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.kanwil is 'Profil Kantor Wilayah (tingkat provinsi). Dibuat oleh user tingkat DITJEN.';

-- =========================================================================
-- TABEL UPT (Unit Pelaksana Teknis - tingkat kabupaten/kota)
-- Berada di bawah otoritas satu Kanwil.
-- =========================================================================
create table if not exists public.upt (
  id         uuid primary key default gen_random_uuid(),
  kanwil_id  uuid not null references public.kanwil(id) on delete restrict,
  nama       text not null,
  jenis      text not null check (jenis in (
               'Balai Pemasyarakatan',
               'Lembaga Pemasyarakatan',
               'Rumah Tahanan Negara',
               'Lembaga Pembinaan Khusus Anak'
             )),
  alamat     text,
  kepala     text,          -- nama Kepala UPT
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.upt is 'Profil Unit Pelaksana Teknis (Bapas/Lapas/Rutan/LPKA). Dibuat oleh DITJEN atau KANWIL pemilik wilayah.';

create index if not exists idx_upt_kanwil_id on public.upt(kanwil_id);

-- =========================================================================
-- TABEL DITJEN_PROFILE (Direktorat Jenderal Pemasyarakatan - tingkat nasional)
-- Singleton: hanya ada 1 baris (id selalu 1).
-- =========================================================================
create table if not exists public.ditjen_profile (
  id         int primary key default 1 check (id = 1),
  nama       text not null default 'Direktorat Jenderal Pemasyarakatan',
  alamat     text,
  dirjen     text,          -- nama Direktur Jenderal
  updated_at timestamptz not null default now()
);

comment on table public.ditjen_profile is 'Profil Direktorat Jenderal Pemasyarakatan (singleton, tingkat nasional).';

insert into public.ditjen_profile (id, nama)
values (1, 'Direktorat Jenderal Pemasyarakatan')
on conflict (id) do nothing;

-- =========================================================================
-- TAMBAH LEVEL & RELASI ORGANISASI KE USERS
-- =========================================================================
alter table public.users
  add column if not exists tingkat   text not null default 'UPT' check (tingkat in ('UPT', 'KANWIL', 'DITJEN')),
  add column if not exists upt_id    uuid references public.upt(id),
  add column if not exists kanwil_id uuid references public.kanwil(id);

comment on column public.users.tingkat is 'Level organisasi user: UPT (kab/kota), KANWIL (provinsi), atau DITJEN (nasional).';
comment on column public.users.upt_id is 'Wajib diisi jika tingkat = UPT, mengacu ke UPT tempat user bertugas.';
comment on column public.users.kanwil_id is 'Wajib diisi jika tingkat = KANWIL, mengacu ke Kanwil tempat user bertugas.';

-- =========================================================================
-- TAMBAH RELASI UPT KE HASIL_ASESMEN
-- upt_id = UPT (Bapas) tempat asesor yang menginput data bertugas, diisi
-- otomatis oleh Edge Function dari sesi login (bukan dari form), dipakai
-- untuk pemantauan berjenjang oleh Kanwil/Ditjen. Ini berbeda dari kolom
-- "UPT/Kanwil" bebas di dalam payload form yang menjelaskan Lapas/Rutan
-- tempat narapidana ditahan.
-- =========================================================================
alter table public.hasil_asesmen
  add column if not exists upt_id uuid references public.upt(id);

create index if not exists idx_hasil_asesmen_upt_id on public.hasil_asesmen(upt_id);

-- =========================================================================
-- ROW LEVEL SECURITY (tanpa policy, sama seperti tabel lain -- akses hanya
-- lewat Edge Function "api" yang memakai service_role key)
-- =========================================================================
alter table public.kanwil enable row level security;
alter table public.upt enable row level security;
alter table public.ditjen_profile enable row level security;

-- =========================================================================
-- SEED DATA: Kanwil & UPT awal berdasarkan data organisasi yang sudah ada
-- (seluruh user/data asesmen saat ini berasal dari Bapas Kelas II Ciangir).
-- Nama/alamat dapat diubah kemudian lewat halaman "Kelola Wilayah".
-- =========================================================================
do $$
declare
  v_kanwil_id uuid;
  v_upt_id uuid;
begin
  insert into public.kanwil (nama, provinsi)
  values ('Kantor Wilayah Kementerian Hukum dan HAM Banten', 'Banten')
  returning id into v_kanwil_id;

  insert into public.upt (kanwil_id, nama, jenis)
  values (v_kanwil_id, 'Bapas Kelas II Ciangir', 'Balai Pemasyarakatan')
  returning id into v_upt_id;

  -- Tautkan seluruh user existing (semuanya tingkat UPT) ke UPT seed ini.
  update public.users set upt_id = v_upt_id where tingkat = 'UPT' and upt_id is null;

  -- Tautkan seluruh data asesmen existing ke UPT seed ini.
  update public.hasil_asesmen set upt_id = v_upt_id where upt_id is null;
end $$;
