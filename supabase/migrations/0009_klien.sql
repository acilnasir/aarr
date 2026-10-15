-- Modul Registrasi: database klien Balai Pemasyarakatan (per UPT).
create table if not exists public.klien (
  id uuid primary key default gen_random_uuid(),
  upt_id uuid not null references public.upt(id) on delete restrict,
  no_register text not null,
  nik text,
  nama text not null,
  tanggal_lahir date,
  agama text,
  kewarganegaraan text default 'WNI',
  pendidikan_terakhir text,
  pekerjaan text,
  status_pernikahan text,
  alamat text,
  no_hp text,
  nama_penjamin text,
  no_hp_penjamin text,
  perkara text,
  pasal text,
  lama_pidana text,
  asal_instansi text,
  foto text,
  created_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (upt_id, no_register)
);
create index if not exists idx_klien_upt on public.klien (upt_id);
create index if not exists idx_klien_nama on public.klien (nama);

-- Tanpa policy: hanya bisa diakses lewat Edge Function (service role).
alter table public.klien enable row level security;
