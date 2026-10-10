import {createClient} from '@supabase/supabase-js';
export const supabase=createClient(import.meta.env.VITE_SUPABASE_URL,import.meta.env.VITE_SUPABASE_ANON_KEY);
export async function api(path,opts={}){const {data}=await supabase.auth.getSession();const t=data.session?.access_token;
 const r=await fetch((import.meta.env.VITE_API_URL||'http://localhost:4000')+path,{...opts,headers:{'content-type':'application/json',...(t?{Authorization:'Bearer '+t}:{})},body:opts.body?JSON.stringify(opts.body):undefined});
 if(r.status===204)return null;const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Request failed ('+r.status+')');return j}
