-- Koordinat perkiraan alamat klien (hasil geocoding) untuk peta pelacakan.
alter table public.klien
  add column if not exists lat double precision,
  add column if not exists lng double precision;

comment on column public.klien.lat is 'Latitude perkiraan dari alamat registrasi (geocoding).';
comment on column public.klien.lng is 'Longitude perkiraan dari alamat registrasi (geocoding).';
