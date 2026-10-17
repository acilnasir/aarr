-- Data pembimbingan klien (dari rekap Bapas): dipakai untuk impor data klien.
alter table public.klien
  add column if not exists jenis_kelamin text,
  add column if not exists pk text,
  add column if not exists jenis_integrasi text,
  add column if not exists kategori text,
  add column if not exists tanggal_penerimaan date,
  add column if not exists tanggal_ekspirasi date,
  add column if not exists status_pembimbingan text,
  add column if not exists daerah text;
