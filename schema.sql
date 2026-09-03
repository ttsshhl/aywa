-- ============================================================
--  Айва — схема базы. Выполнить в Supabase → SQL Editor целиком.
--  Повторный запуск безопасен.
-- ============================================================

-- ── таблицы ────────────────────────────────────────────────

create table if not exists public.profiles (
  id         uuid primary key references auth.users on delete cascade,
  name       text,
  created_at timestamptz default now()
);

create table if not exists public.owners (            -- кто видит панель владельца
  user_id    uuid primary key references auth.users on delete cascade
);

create table if not exists public.listings (
  id          text primary key,
  seller_id   uuid references auth.users on delete set null,
  seller_name text,
  title       text not null,
  tagline     text,
  cat         text,
  price       bigint not null default 0,
  mrr         bigint not null default 0,
  users_text  text,
  age_text    text,
  stack       text,
  description text,
  why         text,
  includes    jsonb not null default '[]'::jsonb,
  shots       jsonb not null default '[]'::jsonb,     -- ссылки на скриншоты
  status      text not null default 'На проверке',
  created_at  timestamptz default now()
);
create index if not exists listings_status_idx on public.listings(status, created_at desc);

create table if not exists public.orders (
  id         text primary key,
  listing_id text references public.listings on delete set null,
  buyer_id   uuid references auth.users on delete set null,
  buyer_name text,
  seller_id  uuid references auth.users on delete set null,
  title      text,
  price      bigint not null default 0,
  status     text not null default 'Ожидает оплаты',
  created_at timestamptz default now()
);

create table if not exists public.order_events (
  id         bigserial primary key,
  order_id   text references public.orders on delete cascade,
  text       text,
  created_at timestamptz default now()
);

create table if not exists public.threads (
  id          text primary key,
  listing_id  text references public.listings on delete cascade,
  buyer_id    uuid references auth.users on delete set null,
  seller_name text,
  title       text,
  price       bigint,
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

create table if not exists public.messages (
  id         bigserial primary key,
  thread_id  text references public.threads on delete cascade,
  sender_id  uuid references auth.users on delete set null,
  kind       text default 'user',
  body       text,
  created_at timestamptz default now()
);

-- ── кто есть кто ───────────────────────────────────────────

create or replace function public.is_owner() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.owners where user_id = auth.uid());
$$;

-- ── RLS ────────────────────────────────────────────────────

alter table public.profiles     enable row level security;
alter table public.owners       enable row level security;
alter table public.listings     enable row level security;
alter table public.orders       enable row level security;
alter table public.order_events enable row level security;
alter table public.threads      enable row level security;
alter table public.messages     enable row level security;

drop policy if exists "профили видны всем" on public.profiles;
create policy "профили видны всем" on public.profiles for select using (true);
drop policy if exists "свой профиль" on public.profiles;
create policy "свой профиль" on public.profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists "правка своего профиля" on public.profiles;
create policy "правка своего профиля" on public.profiles for update to authenticated using (id = auth.uid());

drop policy if exists "список владельцев" on public.owners;
create policy "список владельцев" on public.owners for select to authenticated using (user_id = auth.uid());

drop policy if exists "каталог: опубликованные и свои" on public.listings;
create policy "каталог: опубликованные и свои" on public.listings for select
  using (status = 'Опубликовано' or seller_id = auth.uid() or public.is_owner());
drop policy if exists "объявление создаёт автор" on public.listings;
create policy "объявление создаёт автор" on public.listings for insert to authenticated
  with check (seller_id = auth.uid());
drop policy if exists "правит автор или владелец" on public.listings;
create policy "правит автор или владелец" on public.listings for update to authenticated
  using (seller_id = auth.uid() or public.is_owner());

drop policy if exists "сделки сторон" on public.orders;
create policy "сделки сторон" on public.orders for select to authenticated
  using (buyer_id = auth.uid() or seller_id = auth.uid() or public.is_owner());
drop policy if exists "сделку создаёт покупатель" on public.orders;
create policy "сделку создаёт покупатель" on public.orders for insert to authenticated
  with check (buyer_id = auth.uid());
drop policy if exists "статус меняют стороны" on public.orders;
create policy "статус меняют стороны" on public.orders for update to authenticated
  using (buyer_id = auth.uid() or seller_id = auth.uid() or public.is_owner());

drop policy if exists "события своих сделок" on public.order_events;
create policy "события своих сделок" on public.order_events for select to authenticated
  using (exists (select 1 from public.orders o where o.id = order_id
                 and (o.buyer_id = auth.uid() or o.seller_id = auth.uid() or public.is_owner())));
drop policy if exists "событие пишет сторона" on public.order_events;
create policy "событие пишет сторона" on public.order_events for insert to authenticated
  with check (exists (select 1 from public.orders o where o.id = order_id
                      and (o.buyer_id = auth.uid() or o.seller_id = auth.uid() or public.is_owner())));

drop policy if exists "свои переписки" on public.threads;
create policy "свои переписки" on public.threads for select to authenticated
  using (buyer_id = auth.uid() or public.is_owner()
         or exists (select 1 from public.listings l where l.id = listing_id and l.seller_id = auth.uid()));
drop policy if exists "переписку заводит покупатель" on public.threads;
create policy "переписку заводит покупатель" on public.threads for insert to authenticated
  with check (buyer_id = auth.uid());

drop policy if exists "сообщения своих переписок" on public.messages;
create policy "сообщения своих переписок" on public.messages for select to authenticated
  using (exists (select 1 from public.threads t where t.id = thread_id
                 and (t.buyer_id = auth.uid() or public.is_owner()
                      or exists (select 1 from public.listings l where l.id = t.listing_id and l.seller_id = auth.uid()))));
drop policy if exists "пишет участник" on public.messages;
create policy "пишет участник" on public.messages for insert to authenticated
  with check (sender_id = auth.uid() and exists (select 1 from public.threads t where t.id = thread_id
              and (t.buyer_id = auth.uid()
                   or exists (select 1 from public.listings l where l.id = t.listing_id and l.seller_id = auth.uid()))));

-- ── хранилище скриншотов ───────────────────────────────────
-- Файлы лежат по пути <id пользователя>/<id объявления>/<n>.jpg,
-- поэтому загружать в чужую папку нельзя.

insert into storage.buckets (id, name, public)
values ('shots', 'shots', true)
on conflict (id) do update set public = true;

drop policy if exists "скриншоты читают все" on storage.objects;
create policy "скриншоты читают все" on storage.objects for select
  using (bucket_id = 'shots');

drop policy if exists "загрузка в свою папку" on storage.objects;
create policy "загрузка в свою папку" on storage.objects for insert to authenticated
  with check (bucket_id = 'shots' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "правка своих файлов" on storage.objects;
create policy "правка своих файлов" on storage.objects for update to authenticated
  using (bucket_id = 'shots' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "удаление своих файлов" on storage.objects;
create policy "удаление своих файлов" on storage.objects for delete to authenticated
  using (bucket_id = 'shots' and (storage.foldername(name))[1] = auth.uid()::text);

-- ── себя в владельцы (подставьте свою почту) ───────────────
-- insert into public.owners (user_id)
-- select id from auth.users where email = 'fixakk@yandex.ru'
-- on conflict do nothing;
