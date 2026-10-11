-- Waktu edit terakhir asesmen (untuk sort/filter "baru diedit").
alter table public.hasil_asesmen add column if not exists updated_at timestamptz not null default now();
update public.hasil_asesmen set updated_at = created_at;

create or replace function public.set_updated_at() returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_hasil_asesmen_updated_at on public.hasil_asesmen;
create trigger trg_hasil_asesmen_updated_at
  before update on public.hasil_asesmen
  for each row execute function public.set_updated_at();

create index if not exists idx_hasil_asesmen_updated_at on public.hasil_asesmen (updated_at desc);
