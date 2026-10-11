-- Status penandatangan asesmen per user: asesor, wali, dan/atau nakes (tenaga kesehatan).
-- Satu user boleh memiliki lebih dari satu status.
alter table public.users
  add column if not exists status_penandatangan text[] not null default '{}',
  drop constraint if exists users_status_penandatangan_check;

alter table public.users
  add constraint users_status_penandatangan_check
  check (status_penandatangan <@ array['asesor', 'wali', 'nakes']::text[]);

comment on column public.users.status_penandatangan is 'Status user dalam asesmen: asesor, wali, nakes (boleh lebih dari satu).';

-- Isi awal berdasarkan teks peran/jabatan yang sudah ada.
update public.users set status_penandatangan = array_remove(array[
  case when peran ~* 'asesor|^pk |pembimbing kemasyarakatan|kepala bapas' then 'asesor' end,
  case when peran ~* 'wali' then 'wali' end,
  case when peran ~* 'kesehatan|dokter|perawat|nakes|^dr' then 'nakes' end
], null)
where tingkat = 'UPT' and status_penandatangan = '{}';
