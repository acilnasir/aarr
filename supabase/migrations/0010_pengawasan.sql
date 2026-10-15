-- Modul Pengawasan: pelacakan lokasi klien.
-- Titik pusat & radius wilayah izin per klien (opsional).
alter table public.klien
  add column if not exists wilayah_izin text,
  add column if not exists lat_pusat double precision,
  add column if not exists long_pusat double precision,
  add column if not exists radius_km double precision;

create table if not exists public.presensi_klien (
  id uuid primary key default gen_random_uuid(),
  klien_id uuid not null references public.klien(id) on delete cascade,
  waktu timestamptz not null default now(),
  latitude double precision not null,
  longitude double precision not null,
  baterai integer,
  pekerjaan text,
  alamat_domisili text,
  kendala text,
  foto text
);
create index if not exists idx_presensi_klien_waktu on public.presensi_klien (klien_id, waktu desc);

-- Tanpa policy: hanya bisa diakses lewat Edge Function (service role).
alter table public.presensi_klien enable row level security;
