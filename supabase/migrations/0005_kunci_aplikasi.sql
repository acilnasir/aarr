-- Status kunci aplikasi (tutup/buka input asesmen) per lingkup:
--   DITJEN (nasional, ref_id ''), KANWIL (ref_id = kanwil.id), UPT (ref_id = upt.id).
-- Tidak ada baris = terbuka. Kunci berlaku bagi user UPT di bawah lingkup tsb.
create table if not exists public.kunci_aplikasi (
  scope      text not null check (scope in ('DITJEN','KANWIL','UPT')),
  ref_id     text not null default '',
  locked     boolean not null default false,
  updated_by text,
  updated_at timestamptz not null default now(),
  primary key (scope, ref_id)
);
alter table public.kunci_aplikasi enable row level security;
