-- Foto profil user (data URL JPEG persegi kecil).
alter table public.users add column if not exists foto text;
