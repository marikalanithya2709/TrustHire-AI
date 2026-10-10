-- Run in Supabase > SQL Editor
create table profiles(id uuid primary key references auth.users on delete cascade,name text,preferred_role text,education text,location text,created_at timestamptz default now());
create table opportunities(id uuid primary key default gen_random_uuid(),user_id uuid not null references auth.users on delete cascade,company_name text not null,role text,opportunity_type text,description text,url text,company_website text,recruiter_name text,recruiter_email text,recruiter_phone text,salary text,location text,recruiter_message text,created_at timestamptz default now());
create table analyses(id uuid primary key default gen_random_uuid(),opportunity_id uuid not null references opportunities on delete cascade,user_id uuid not null references auth.users on delete cascade,risk_score int not null check(risk_score between 0 and 100),risk_level text not null,method text not null,summary text,indicators jsonb not null default '[]',positives jsonb not null default '[]',ai_summary text,created_at timestamptz default now());
create table saved_opportunities(id uuid primary key default gen_random_uuid(),user_id uuid not null references auth.users on delete cascade,analysis_id uuid not null references analyses on delete cascade,notes text,created_at timestamptz default now(),unique(user_id,analysis_id));
create table community_reports(id uuid primary key default gen_random_uuid(),user_id uuid not null references auth.users on delete cascade,company_name text not null,title text,description text not null,source_url text,report_date date,status text not null default 'pending' check(status in('pending','approved','rejected')),created_at timestamptz default now());
create index on opportunities(user_id);create index on analyses(user_id,created_at desc);create index on saved_opportunities(user_id);create index on community_reports(status,created_at desc);
alter table profiles enable row level security;alter table opportunities enable row level security;alter table analyses enable row level security;alter table saved_opportunities enable row level security;alter table community_reports enable row level security;
create policy own_profile on profiles for all using(id=auth.uid()) with check(id=auth.uid());
create policy own_opp on opportunities for all using(user_id=auth.uid()) with check(user_id=auth.uid());
create policy own_an on analyses for all using(user_id=auth.uid()) with check(user_id=auth.uid());
create policy own_saved on saved_opportunities for all using(user_id=auth.uid()) with check(user_id=auth.uid());
create policy read_approved on community_reports for select using(status='approved' or user_id=auth.uid());
create policy add_report on community_reports for insert with check(user_id=auth.uid() and status='pending');
-- moderation: approve reports manually in Supabase Table Editor (set status='approved')
create function handle_new_user() returns trigger language plpgsql security definer as $$ begin insert into profiles(id,name) values(new.id,split_part(new.email,'@',1)); return new; end $$;
create trigger on_signup after insert on auth.users for each row execute function handle_new_user();
