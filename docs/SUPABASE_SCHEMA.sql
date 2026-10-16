-- Supabase schema for Swarm Core Security subscription sync.
-- The Stripe webhook (server/stripe_webhook.js) upserts here; mobile clients
-- read their tier after Apple/Google receipt validation.

create table if not exists user_profiles (
    id uuid primary key default gen_random_uuid(),
    email_address text unique not null,
    subscription_tier_allocation smallint not null default 0
        check (subscription_tier_allocation in (0, 1)), -- 0 freemium, 1 pro
    stripe_customer_id text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_user_profiles_email
    on user_profiles (email_address);

-- Keep updated_at fresh.
create or replace function touch_updated_at()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_user_profiles_touch on user_profiles;
create trigger trg_user_profiles_touch
    before update on user_profiles
    for each row execute function touch_updated_at();

-- Row-level security: users read only their own row (auth.email()).
alter table user_profiles enable row level security;

drop policy if exists "self read" on user_profiles;
create policy "self read"
    on user_profiles for select
    using (auth.email() = email_address);
-- Writes go through the service-role key in the webhook only.
