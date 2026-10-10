import test from 'node:test';import assert from 'node:assert/strict';import {analyze,validate} from '../src/engine.js';
const run=o=>analyze(validate({company_name:'X',description:'x'.repeat(200),...o}).value);
test('payment request flagged',()=>{const r=run({description:'Pay registration fee Rs 1500 today to confirm your seat. '.repeat(3)});assert.ok(r.indicators.some(i=>i.category==='payment'));assert.ok(r.risk_score>=30)});
test('OTP request flagged',()=>assert.ok(run({recruiter_message:'Share your OTP and bank account'}).indicators.some(i=>i.category==='sensitive')));
test('unrealistic pay flagged',()=>assert.ok(run({recruiter_message:'Earn 50000 per day guaranteed income'}).indicators.some(i=>i.category==='compensation')));
test('suspicious url flagged',()=>assert.ok(run({url:'http://bit.ly/abc'}).indicators.some(i=>i.category==='url')));
test('multiple indicators capped at 100',()=>{const r=run({recruiter_message:'Pay registration fee. Share OTP. No interview. Earn 5000 per day. Join immediately. WhatsApp us',url:'http://bit.ly/x',recruiter_email:'a@gmail.com'});assert.ok(r.risk_score<=100&&r.risk_level==='CRITICAL RISK')});
test('clean posting is low risk, never "safe"',()=>{const r=run({description:'Responsibilities: build APIs. Requirements: JS skills. Interview with HR round and technical round. '.repeat(3),recruiter_email:'hr@acme.com',company_website:'https://acme.com'});assert.equal(r.risk_level,'LOW RISK');assert.match(r.limitations,/does not mean/)});
test('validation rejects empty and bad email',()=>{assert.ok(validate({}).errors.length>=2);assert.ok(validate({company_name:'A',description:'d',recruiter_email:'nope'}).errors.length)});
