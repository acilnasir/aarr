-- Tanda tangan digital untuk pengesahan asesmen (Wali Pemasyarakatan,
-- Asesor, Tenaga Kesehatan).

-- Gambar tanda tangan tiap user disimpan sebagai data URL (PNG/JPEG kecil).
alter table public.users add column if not exists tanda_tangan text;

-- Penandatangan pada setiap asesmen. Disimpan sebagai kolom terpisah (bukan di
-- payload) supaya format array posisional lama tetap utuh.
alter table public.hasil_asesmen add column if not exists asesor_username text;
alter table public.hasil_asesmen add column if not exists wali_username text;
alter table public.hasil_asesmen add column if not exists nakes_username text;

-- Backfill asesor untuk data lama: cocokkan nama asesor (payload[0]) dengan
-- user pada UPT yang sama.
update public.hasil_asesmen h
set asesor_username = u.username
from public.users u
where h.asesor_username is null
  and u.upt_id = h.upt_id
  and u.nama = h.payload->>0;
