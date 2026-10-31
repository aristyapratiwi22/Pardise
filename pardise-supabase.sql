-- PARDISE: skema autentikasi, profil, peran, dan RLS
-- Jalankan di Supabase Dashboard > SQL Editor (sekali saja).

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  username text not null,
  phone text,
  farm_name text,
  farm_location text,
  avatar_url text,
  role text not null default 'user' check (role in ('admin','user')),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index profiles_username_key on public.profiles (lower(username));
alter table public.profiles enable row level security;

-- Pemeriksaan admin (security definer agar tidak rekursif di RLS)
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin' and is_active);
$$;

-- Pengguna hanya melihat/mengubah profilnya sendiri; admin dapat semuanya.
-- Tidak ada policy INSERT/DELETE: profil dibuat oleh trigger saja.
create policy "profiles_select" on public.profiles for select
  using (id = auth.uid() or public.is_admin());
create policy "profiles_update" on public.profiles for update
  using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());

-- Buat profil otomatis saat registrasi (peran selalu 'user')
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, username, farm_name, farm_location)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email,'@',1)),
    coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)),
    nullif(new.raw_user_meta_data->>'farm_name',''),
    nullif(new.raw_user_meta_data->>'farm_location','')
  );
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Cegah pengguna biasa menaikkan peran / mengaktifkan dirinya sendiri
create or replace function public.guard_profile_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    new.role := old.role;
    new.is_active := old.is_active;
  end if;
  new.updated_at := now();
  return new;
end $$;
create trigger profiles_guard before update on public.profiles
  for each row execute function public.guard_profile_update();

-- Login dengan username: cari email-nya (dapat dipanggil sebelum login)
create or replace function public.email_for_login(p_username text) returns text
language sql security definer stable set search_path = public as $$
  select u.email::text from auth.users u
  join public.profiles p on p.id = u.id
  where lower(p.username) = lower(p_username) limit 1;
$$;
create or replace function public.username_available(p_username text) returns boolean
language sql security definer stable set search_path = public as $$
  select not exists (select 1 from public.profiles where lower(username) = lower(p_username));
$$;
grant execute on function public.email_for_login(text), public.username_available(text) to anon, authenticated;

-- Penyimpanan foto profil: tiap pengguna hanya menulis di foldernya sendiri
insert into storage.buckets (id, name, public) values ('avatars','avatars',true)
  on conflict (id) do nothing;
create policy "avatars_read" on storage.objects for select using (bucket_id = 'avatars');
create policy "avatars_write" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatars_update" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatars_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- POLA untuk semua tabel data petani (lahan, siklus, RAB, hama, laporan):
create table public.lahan (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  nama text not null,
  luas_m2 numeric,
  created_at timestamptz not null default now()
);
alter table public.lahan enable row level security;
create policy "lahan_owner_or_admin" on public.lahan for all
  using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());

-- Tabel master (komoditas, hama_penyakit): semua login boleh baca, hanya admin menulis.
-- create policy "read" on public.komoditas for select to authenticated using (true);
-- create policy "admin_write" on public.komoditas for all using (public.is_admin()) with check (public.is_admin());

-- Menjadikan akun pertama sebagai Administrator (ganti emailnya, jalankan di SQL Editor):
-- update public.profiles set role = 'admin'
--   where id = (select id from auth.users where email = 'email-anda@contoh.com');
