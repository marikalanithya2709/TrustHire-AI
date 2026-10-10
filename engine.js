// Deterministic, explainable scam-risk engine. Each rule counts at most once.
export const WEIGHTS={payment:30,sensitive:25,url:20,contact:15,compensation:15,company:15,nointerview:15,pressure:10,channel:8,vague:5};
export const LEVELS=[[80,'CRITICAL RISK'],[60,'HIGH RISK'],[30,'MODERATE RISK'],[0,'LOW RISK']];
const FREE=['gmail.com','yahoo.com','outlook.com','hotmail.com','rediffmail.com','ymail.com','proton.me'];
const RULES=[
['payment','Payment request','Critical',/\b(registration|application|interview|training|security|processing|kit|joining|refundable)\s*(fee|deposit|charges?)\b|\bpay\s+(rs\.?|₹|inr|\$)?\s*\d+|\bpay\s+to\s+(join|get)/i,'Applicants are asked to pay money.','Do not pay before independently verifying the employer.'],
['sensitive','Sensitive information request','Critical',/\b(otp|pin\b|password|cvv|card number|bank account|account number|net ?banking)\b/i,'Sensitive financial or login data is requested.','Never share OTPs, PINs, passwords or banking details.'],
['nointerview','Hiring without interview','High',/(no|without)\s+interview|selected\s+(immediately|directly)|you\s+are\s+(already\s+)?selected/i,'Selection skips a normal hiring process.','Expect an interview via official channels.'],
['compensation','Unrealistic compensation','High',/guaranteed\s+(job|placement|income|salary)|earn\s+.{0,25}(per\s+day|daily|weekly)|easy\s+money|100%\s+placement/i,'Guaranteed or unusually high earnings are claimed.','Compare with market pay for the role.'],
['pressure','High-pressure tactics','Medium',/pay\s+today|join\s+immediately|limited\s+(slots|seats|time)|within\s+\d+\s*(hours|hrs)|last\s+chance|act\s+now/i,'Urgency is used to rush your decision.','Take time; legitimate employers allow verification.'],
['channel','Unofficial communication channel','Medium',/whats\s?app|telegram/i,'Conversation is pushed to a messaging app.','Prefer official company email/portal.']];
const host=u=>{try{return new URL(/^https?:/i.test(u)?u:'https://'+u).hostname.replace(/^www\./,'').toLowerCase()}catch{return''}};
export function validate(b={}){const s=(k,n=200)=>String(b[k]??'').trim().slice(0,n),e=[];
 const v={company_name:s('company_name',120),role:s('role',120),opportunity_type:['Job','Internship','Freelance','Work From Home','Other'].includes(b.opportunity_type)?b.opportunity_type:'Job',description:s('description',6000),url:s('url',300),company_website:s('company_website',200),recruiter_name:s('recruiter_name',100),recruiter_email:s('recruiter_email',120).toLowerCase(),recruiter_phone:s('recruiter_phone',30),salary:s('salary',80),location:s('location',100),recruiter_message:s('recruiter_message',4000)};
 if(!v.company_name)e.push('Company name is required');
 if(!v.description&&!v.recruiter_message)e.push('Provide a job description or recruiter message');
 if(v.recruiter_email&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.recruiter_email))e.push('Recruiter email is invalid');
 for(const k of['url','company_website'])if(v[k]&&!host(v[k]))e.push(k+' is not a valid URL');
 return{value:v,errors:e}}
export function urlFindings(u){const out=[];if(!u)return out;let x;try{x=new URL(/^https?:/i.test(u)?u:'https://'+u)}catch{return[]}const h=x.hostname;
 if(x.protocol==='http:')out.push('Link does not use HTTPS');
 if(/^\d+\.\d+\.\d+\.\d+$/.test(h))out.push('Link uses a raw IP address');
 if(/^(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd)$/.test(h))out.push('Shortened link hides the destination');
 if(/xn--/.test(h)||(h.match(/-/g)||[]).length>2)out.push('Unusual domain structure');
 if(/(login|verify|secure|bonus|claim)/i.test(h))out.push('Phishing-style keyword in domain');return out}
export function analyze(v){const text=[v.description,v.recruiter_message,v.role,v.salary].join('\n'),ind=[],pos=[];
 for(const[k,t,sev,re,ex,rec]of RULES){const m=text.match(re);if(m)ind.push({category:k,title:t,severity:sev,evidence:m[0],explanation:ex,recommendation:rec,weight:WEIGHTS[k]})}
 const uf=[...urlFindings(v.url),...urlFindings(v.company_website)];
 if(uf.length)ind.push({category:'url',title:'Suspicious link pattern',severity:'High',evidence:uf.join('; '),explanation:'URL structure resembles phishing or hides its destination.',recommendation:'Do not enter data; open the company site yourself.',weight:WEIGHTS.url});
 const ed=v.recruiter_email.split('@')[1]||'',sh=host(v.company_website);
 if(ed&&FREE.includes(ed))ind.push({category:'contact',title:'Free email domain for recruiter',severity:'Medium',evidence:v.recruiter_email,explanation:'Free email alone is not proof of fraud, but companies usually use their own domain.',recommendation:'Ask for an official company email.',weight:WEIGHTS.contact});
 else if(ed&&sh){const ok=ed===sh||ed.endsWith('.'+sh)||sh.endsWith('.'+ed);ok?pos.push({title:'Recruiter email matches company website',explanation:ed+' and '+sh+' are consistent (not proof of legitimacy).'}):ind.push({category:'company',title:'Email and website domain mismatch',severity:'High',evidence:ed+' vs '+sh,explanation:'Recruiter domain differs from the stated company website.',recommendation:'Verify the recruiter through the official site.',weight:WEIGHTS.company})}
 if(v.description&&v.description.length<150)ind.push({category:'vague',title:'Vague job description',severity:'Low',evidence:v.description.length+' characters',explanation:'Little detail on duties or requirements.',recommendation:'Request a detailed description.',weight:WEIGHTS.vague});
 else if(/responsibilit|requirement|qualification|skills/i.test(v.description))pos.push({title:'Detailed job description',explanation:'Mentions responsibilities or requirements.'});
 if(/interview|assessment|hr round|technical round/i.test(text))pos.push({title:'Interview process mentioned',explanation:'Text references a hiring process.'});
 if(!ind.some(i=>i.category==='payment')&&text.length>50)pos.push({title:'No payment request detected',explanation:'No fee or deposit language found.'});
 const score=Math.min(100,ind.reduce((a,i)=>a+i.weight,0)),level=LEVELS.find(l=>score>=l[0])[1];
 return{risk_score:score,risk_level:level,method:'rules',summary:`${ind.length} warning indicator(s) and ${pos.length} positive signal(s). Estimated risk, not certainty.`,indicators:ind,positives:pos,limitations:'Text-based heuristics only. No company registration or website ownership is verified. Absence of red flags does not mean an offer is safe.'}}
