-- KN Wave.lk database (Supabase / PostgreSQL). Run once in Supabase > SQL Editor.
create extension if not exists pgcrypto with schema extensions;

create table public.services (
  id text primary key,
  name jsonb not null,          -- {"en":"..","si":"..","ta":".."}
  description jsonb not null,
  price_text jsonb not null,
  active boolean not null default true,
  sort int not null default 0,
  updated_at timestamptz not null default now()
);

create table public.reviews (
  id uuid primary key default gen_random_uuid(),
  service_id text not null references public.services(id) on update cascade,
  rating smallint not null check (rating between 1 and 5),
  emotion text not null check (emotion in ('laugh','happy','neutral','sad','angry')),
  comment text not null check (char_length(comment) between 10 and 1000),
  display_name text check (display_name is null or char_length(display_name) <= 40),
  lang text not null default 'en' check (lang in ('en','si','ta')),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  moderated_at timestamptz,
  moderated_by uuid references auth.users(id) on delete set null,
  ip_hash text                  -- salted hash only, used for rate limiting, never public
);
create index reviews_status_created on public.reviews (status, created_at desc);
create index reviews_service on public.reviews (service_id);
create index reviews_iphash on public.reviews (ip_hash, created_at);

create table public.admins (user_id uuid primary key references auth.users(id) on delete cascade);
alter table public.admins enable row level security;   -- no policies: not reachable via the API

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.admins where user_id = auth.uid()) $$;

-- Server-side checks: forces "pending", cleans text, rate-limits (3/hour per IP hash), blocks duplicates.
create or replace function public.reviews_before_insert() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare ip text; h text;
begin
  new.status := 'pending'; new.moderated_at := null; new.moderated_by := null;
  new.comment := btrim(new.comment);
  new.display_name := nullif(btrim(coalesce(new.display_name, '')), '');
  begin
    ip := split_part(coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', 'unknown'), ',', 1);
  exception when others then ip := 'unknown'; end;
  h := encode(digest(ip || 'CHANGE-THIS-SALT', 'sha256'), 'hex');
  if (select count(*) from public.reviews where ip_hash = h and created_at > now() - interval '1 hour') >= 3 then
    raise exception 'rate_limited';
  end if;
  if exists (select 1 from public.reviews where ip_hash = h and service_id = new.service_id and comment = new.comment) then
    raise exception 'duplicate';
  end if;
  new.ip_hash := h;
  return new;
end $$;
create trigger trg_reviews_insert before insert on public.reviews for each row execute function public.reviews_before_insert();

create or replace function public.reviews_before_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if new.status is distinct from old.status then new.moderated_at := now(); new.moderated_by := auth.uid(); end if;
  return new;
end $$;
create trigger trg_reviews_update before update on public.reviews for each row execute function public.reviews_before_update();

-- Real stats from approved reviews only
create or replace function public.review_stats() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object('count', count(*), 'avg', coalesce(round(avg(rating), 2), 0),
    'dist', json_build_object('1', count(*) filter (where rating=1), '2', count(*) filter (where rating=2),
      '3', count(*) filter (where rating=3), '4', count(*) filter (where rating=4), '5', count(*) filter (where rating=5)))
  from public.reviews where status = 'approved' $$;

-- Permissions: column-level grants keep ip_hash private
revoke all on public.services, public.reviews, public.admins from anon, authenticated;
grant select on public.services to anon, authenticated;
grant insert, update, delete on public.services to authenticated;
grant select (id, service_id, rating, emotion, comment, display_name, lang, status, created_at) on public.reviews to anon;
grant select (id, service_id, rating, emotion, comment, display_name, lang, status, created_at, moderated_at) on public.reviews to authenticated;
grant insert (service_id, rating, emotion, comment, display_name, lang) on public.reviews to anon, authenticated;
grant update (status) on public.reviews to authenticated;
grant delete on public.reviews to authenticated;
grant execute on function public.review_stats() to anon, authenticated;
grant execute on function public.is_admin() to authenticated;

alter table public.services enable row level security;
alter table public.reviews enable row level security;
create policy services_read on public.services for select using (active or public.is_admin());
create policy services_admin_ins on public.services for insert to authenticated with check (public.is_admin());
create policy services_admin_upd on public.services for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy services_admin_del on public.services for delete to authenticated using (public.is_admin());
create policy reviews_read on public.reviews for select using (status = 'approved' or public.is_admin());
create policy reviews_insert on public.reviews for insert to anon, authenticated with check (status = 'pending');
create policy reviews_admin_upd on public.reviews for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy reviews_admin_del on public.reviews for delete to authenticated using (public.is_admin());

-- Initial services and prices (editable later in the admin dashboard)
insert into public.services (id, sort, name, description, price_text) values
('dancing-track',1,
 '{"en":"Dancing Track Making","si":"නැටුම් ට්‍රැක් නිර්මාණය","ta":"நடன டிராக் உருவாக்கம்"}',
 '{"en":"A dancing track made from your song. The final price depends on the finished track duration and the number of songs or sections included.","si":"ඔබේ ගීතයෙන් නැටුම් ට්‍රැක් එකක් සාදා දෙනු ලැබේ. අවසාන මිල නිමි ට්‍රැක් එකේ කාලසීමාව සහ ඇතුළත් ගීත හෝ කොටස් ගණන අනුව වෙනස් විය හැක.","ta":"உங்கள் பாடலிலிருந்து நடன டிராக் உருவாக்கப்படும். இறுதி விலை முடிந்த டிராக்கின் நீளம் மற்றும் சேர்க்கப்படும் பாடல்கள் அல்லது பகுதிகளின் எண்ணிக்கையைப் பொறுத்தது."}',
 '{"en":"Rs. 50 per minute","si":"රු. 50 (මිනිත්තුවකට)","ta":"ரூ. 50 (நிமிடத்திற்கு)"}'),
('vocal-removal',2,
 '{"en":"Vocal Removal","si":"හඬ ඉවත් කිරීම","ta":"குரல் நீக்கம்"}',
 '{"en":"Removes the vocals from a song. For longer tracks, please confirm the price first.","si":"ගීතයකින් හඬ ඉවත් කරයි. දිගු ගීත සඳහා කරුණාකර මුලින් මිල තහවුරු කරගන්න.","ta":"பாடலிலிருந்து குரலை நீக்குகிறது. நீளமான பாடல்களுக்கு முதலில் விலையை உறுதிப்படுத்தவும்."}',
 '{"en":"Rs. 50 for a 3-minute track","si":"රු. 50 (මිනිත්තු 3 ක ගීතයකට)","ta":"ரூ. 50 (3 நிமிட பாடலுக்கு)"}'),
('drum-removal',3,
 '{"en":"Drum Removal","si":"බෙර ඉවත් කිරීම","ta":"டிரம் நீக்கம்"}',
 '{"en":"Removes drums from a track. The final price depends on the audio and is confirmed before work begins.","si":"ගීතයකින් බෙර ශබ්ද ඉවත් කරයි. අවසාන මිල ශ්‍රව්‍යය අනුව තීරණය වන අතර වැඩ ආරම්භයට පෙර තහවුරු කෙරේ.","ta":"பாடலிலிருந்து டிரம் ஒலிகளை நீக்குகிறது. இறுதி விலை ஆடியோவைப் பொறுத்தது; வேலை தொடங்கும் முன் உறுதிப்படுத்தப்படும்."}',
 '{"en":"Rs. 200–400 for an 8-minute track","si":"රු. 200–400 (මිනිත්තු 8 ක ගීතයකට)","ta":"ரூ. 200–400 (8 நிமிட பாடலுக்கு)"}'),
('karaoke-track',4,
 '{"en":"Instrumental / Karaoke Track","si":"ඉන්ස්ට්‍රුමෙන්ටල් / කැරෝකේ ට්‍රැක්","ta":"இன்ஸ்ட்ருமென்டல் / கரோக்கி டிராக்"}',
 '{"en":"An instrumental or karaoke version of your song. For other durations, please confirm the price first.","si":"ඔබේ ගීතයේ ඉන්ස්ට්‍රුමෙන්ටල් හෝ කැරෝකේ අනුවාදය. වෙනත් කාලසීමා සඳහා මුලින් මිල තහවුරු කරගන්න.","ta":"உங்கள் பாடலின் இன்ஸ்ட்ருமென்டல் அல்லது கரோக்கி பதிப்பு. வேறு நீளங்களுக்கு முதலில் விலையை உறுதிப்படுத்தவும்."}',
 '{"en":"Rs. 50 for a 3-minute track","si":"රු. 50 (මිනිත්තු 3 ක ගීතයකට)","ta":"ரூ. 50 (3 நிமிட பாடலுக்கு)"}'),
('audio-editing',5,
 '{"en":"Audio Editing","si":"ශ්‍රව්‍ය සංස්කරණය","ta":"ஆடியோ எடிட்டிங்"}',
 '{"en":"Cutting, editing and arranging your audio. Tell us what you need to get a quote.","si":"ඔබේ ශ්‍රව්‍ය කැපීම, සංස්කරණය සහ සකස් කිරීම. මිල ගණන් සඳහා ඔබට අවශ්‍ය දේ දන්වන්න.","ta":"உங்கள் ஆடியோவை வெட்டுதல், திருத்துதல், ஒழுங்குபடுத்துதல். விலைப்புள்ளிக்கு உங்கள் தேவையைத் தெரிவிக்கவும்."}',
 '{"en":"Price on request","si":"මිල ඉල්ලීම මත","ta":"விலை கேட்டால் தெரிவிக்கப்படும்"}'),
('audio-enhancement',6,
 '{"en":"Audio Quality Enhancement","si":"ශ්‍රව්‍ය ගුණාත්මකභාවය වැඩිදියුණු කිරීම","ta":"ஆடியோ தர மேம்பாடு"}',
 '{"en":"Improving the clarity and quality of your audio. Results depend on the original recording.","si":"ඔබේ ශ්‍රව්‍යයේ පැහැදිලි බව සහ ගුණාත්මකභාවය වැඩි දියුණු කිරීම. ප්‍රතිඵල මුල් පටිගත කිරීම මත රඳා පවතී.","ta":"உங்கள் ஆடியோவின் தெளிவையும் தரத்தையும் மேம்படுத்துதல். முடிவுகள் அசல் பதிவைப் பொறுத்தது."}',
 '{"en":"Price on request","si":"මිල ඉල්ලීම මත","ta":"விலை கேட்டால் தெரிவிக்கப்படும்"}');

-- FIRST ADMIN (after creating a user in Supabase > Authentication > Users), run:
-- insert into public.admins (user_id) select id from auth.users where email = 'YOUR-ADMIN-EMAIL';
