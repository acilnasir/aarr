-- Wilayah kerja Balai Pemasyarakatan (Bapas): daftar Lapas/Rutan/LPKA yang
-- menjadi cakupan kerja sebuah Bapas. Asesor dari Bapas boleh melaksanakan
-- asesmen di UPT yang termasuk wilayah kerjanya.
create table if not exists public.bapas_wilayah_kerja (
  bapas_id   uuid not null references public.upt(id) on delete cascade,
  upt_id     uuid not null references public.upt(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (bapas_id, upt_id),
  check (bapas_id <> upt_id)
);

comment on table public.bapas_wilayah_kerja is 'Referensi wilayah kerja Bapas: Lapas/Rutan/LPKA (upt_id) yang menjadi cakupan sebuah Bapas (bapas_id).';

create index if not exists idx_bapas_wilayah_upt on public.bapas_wilayah_kerja(upt_id);

-- hasil_asesmen.upt_id = UPT tempat WBP berada (pemilik data).
-- asesor_upt_id = UPT asal asesor (mis. Bapas) bila berbeda dari pemilik data.
alter table public.hasil_asesmen
  add column if not exists asesor_upt_id uuid references public.upt(id);

create index if not exists idx_hasil_asesmen_asesor_upt on public.hasil_asesmen(asesor_upt_id);

alter table public.bapas_wilayah_kerja enable row level security;
