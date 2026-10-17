-- Role baru: MITRA (Mitra Bapas), mis. Babinkamtibmas, Babinsa, Jaksa Pengawas,
-- Kapolsek, Kapolres, Ketua Pengadilan Negeri. Akses baca-saja ke Pelacakan Klien,
-- dibatasi wilayah kewenangan (kota/kabupaten wajib; kecamatan & kelurahan opsional).
alter table public.users drop constraint if exists users_tingkat_check;
alter table public.users
  add constraint users_tingkat_check check (tingkat in ('UPT', 'KANWIL', 'DITJEN', 'MITRA'));

alter table public.users
  add column if not exists mitra_kota text,
  add column if not exists mitra_kec  text,
  add column if not exists mitra_kel  text;

comment on column public.users.mitra_kota is 'MITRA: kota/kabupaten wewenang (sama dengan klien.daerah).';
comment on column public.users.mitra_kec  is 'MITRA: kecamatan wewenang (opsional, dicocokkan ke teks alamat klien).';
comment on column public.users.mitra_kel  is 'MITRA: kelurahan/desa wewenang (opsional, dicocokkan ke teks alamat klien).';
