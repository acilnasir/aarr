-- Modul Litmas: Penelitian Kemasyarakatan + riwayat perubahan.
create table if not exists public.litmas (
  id uuid primary key default gen_random_uuid(),
  upt_id uuid not null references public.upt(id) on delete restrict,
  klien_id uuid not null references public.klien(id) on delete cascade,
  jenis_litmas smallint not null check (jenis_litmas between 1 and 13),
  no_reg_litmas text,
  tgl_laporan text,
  header jsonb not null default '{}'::jsonb,       -- kementerian, kanwil, bapas, alamat
  pendahuluan text,
  identitas jsonb not null default '{}'::jsonb,    -- data identitas klien saat Litmas dibuat
  riwayat jsonb not null default '{}'::jsonb,      -- riwayat hidup, pendidikan/tingkah laku, tindak pidana
  komponen jsonb not null default '{}'::jsonb,     -- komponen spesifik per jenis
  analisis text,
  kesimpulan text,
  rekomendasi text,
  pejabat jsonb not null default '{}'::jsonb,      -- kepala bapas & PK
  versi integer not null default 1,
  created_by text,
  updated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_litmas_upt on public.litmas (upt_id);
create index if not exists idx_litmas_klien on public.litmas (klien_id);

-- Riwayat: setiap simpan/ubah mencatat salinan lengkap (snapshot) sebagai satu versi.
create table if not exists public.litmas_history (
  id uuid primary key default gen_random_uuid(),
  litmas_id uuid not null references public.litmas(id) on delete cascade,
  versi integer not null,
  aksi text not null,
  oleh text,
  waktu timestamptz not null default now(),
  snapshot jsonb not null
);
create index if not exists idx_litmas_history_litmas on public.litmas_history (litmas_id, versi);

alter table public.litmas enable row level security;
alter table public.litmas_history enable row level security;
