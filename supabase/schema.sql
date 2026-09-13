-- Vero production database foundation for Supabase/PostgreSQL.
-- Apply through Supabase SQL editor after creating the project.
create extension if not exists pgcrypto;

create table if not exists public.businesses (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  category text,
  location text,
  phone text,
  email text,
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.business_members (
  business_id uuid not null references public.businesses(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner' check (role in ('owner','admin','staff')),
  created_at timestamptz not null default now(),
  primary key (business_id,user_id)
);

create table if not exists public.customers (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  name text not null,
  phone text,
  email text,
  notes text,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  name text not null,
  description text,
  price numeric(14,2) not null default 0 check (price >= 0),
  category text,
  image_url text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  customer_id uuid references public.customers(id) on delete set null,
  status text not null default 'pending' check (status in ('draft','pending','paid','cancelled','fulfilled')),
  total numeric(14,2) not null default 0 check (total >= 0),
  created_at timestamptz not null default now()
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  customer_id uuid references public.customers(id) on delete set null,
  order_id uuid references public.orders(id) on delete set null,
  type text not null check (type in ('income','expense')),
  amount numeric(14,2) not null check (amount >= 0),
  method text,
  reference text,
  description text,
  occurred_at timestamptz not null default now()
);

create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  customer_id uuid references public.customers(id) on delete set null,
  invoice_number text not null,
  status text not null default 'draft' check (status in ('draft','sent','viewed','part_paid','paid','overdue','cancelled')),
  total numeric(14,2) not null default 0 check (total >= 0),
  due_at timestamptz,
  created_at timestamptz not null default now(),
  unique (business_id, invoice_number)
);

create table if not exists public.expenses (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  amount numeric(14,2) not null check (amount >= 0),
  category text,
  description text,
  occurred_at timestamptz not null default now()
);

create table if not exists public.leads (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  name text,
  phone text,
  email text,
  source text,
  status text not null default 'new' check (status in ('new','contacted','interested','converted','lost')),
  created_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  business_id uuid references public.businesses(id) on delete cascade,
  user_id uuid references auth.users(id) on delete set null,
  action text not null,
  entity_type text,
  entity_id uuid,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Row-level security: users can only read/write records for businesses they belong to.
alter table public.businesses enable row level security;
alter table public.business_members enable row level security;
alter table public.customers enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.transactions enable row level security;
alter table public.invoices enable row level security;
alter table public.expenses enable row level security;
alter table public.leads enable row level security;
alter table public.audit_logs enable row level security;

create or replace function public.is_business_member(target_business uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.business_members bm where bm.business_id = target_business and bm.user_id = auth.uid()); $$;

create policy "members can view businesses" on public.businesses for select using (public.is_business_member(id));
create policy "members can manage businesses" on public.businesses for all using (public.is_business_member(id)) with check (public.is_business_member(id));

create policy "members can view memberships" on public.business_members for select using (user_id = auth.uid() or public.is_business_member(business_id));
create policy "members can manage memberships" on public.business_members for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));

create policy "members customers" on public.customers for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members products" on public.products for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members orders" on public.orders for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members transactions" on public.transactions for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members invoices" on public.invoices for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members expenses" on public.expenses for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members leads" on public.leads for all using (public.is_business_member(business_id)) with check (public.is_business_member(business_id));
create policy "members audit logs" on public.audit_logs for select using (public.is_business_member(business_id));
