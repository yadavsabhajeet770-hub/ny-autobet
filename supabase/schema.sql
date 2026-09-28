create extension if not exists pgcrypto;

create table if not exists public.license_keys (
  id uuid primary key default gen_random_uuid(),
  key_hash text unique not null,
  key_last4 text not null,
  status text not null default 'active' check (status in ('active','disabled','expired')),
  expires_at timestamptz,
  max_devices integer not null default 1 check (max_devices between 1 and 50),
  bound_phone text,
  bound_platform text,
  device_id text,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_used_at timestamptz
);
create index if not exists license_keys_hash_idx on public.license_keys(key_hash);
create index if not exists license_keys_status_idx on public.license_keys(status);

create table if not exists public.license_sessions (
  id uuid primary key default gen_random_uuid(),
  license_id uuid not null references public.license_keys(id) on delete cascade,
  session_token_hash text unique not null,
  phone text,
  platform text,
  device_id text,
  ip_hash text,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  stopped_at timestamptz
);
create index if not exists license_sessions_license_idx on public.license_sessions(license_id);
create index if not exists license_sessions_active_idx on public.license_sessions(license_id,stopped_at,last_seen_at);


create table if not exists public.admin_sessions (
  id uuid primary key default gen_random_uuid(),
  token_hash text unique not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists admin_sessions_active_idx on public.admin_sessions(token_hash,expires_at,revoked_at);
alter table public.admin_sessions enable row level security;

create table if not exists public.admin_audit_logs (
  id bigint generated always as identity primary key,
  action text not null,
  target text,
  details jsonb,
  created_at timestamptz not null default now()
);
create index if not exists admin_audit_logs_created_idx on public.admin_audit_logs(created_at desc);

alter table public.license_keys enable row level security;
alter table public.license_sessions enable row level security;
alter table public.admin_audit_logs enable row level security;

-- Migration from the earlier package: run only if your old table used plaintext `key`.
-- alter table public.license_keys add column if not exists key_hash text;
-- alter table public.license_keys add column if not exists key_last4 text;
-- Backfill key_hash/key_last4 before dropping the old plaintext key column.
