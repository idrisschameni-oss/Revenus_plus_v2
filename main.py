import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt, JWTError
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DB=os.getenv('DATABASE_URL','sqlite:///./revenus_plus.db')
if DB.startswith('postgres://'): DB=DB.replace('postgres://','postgresql+psycopg2://',1)
elif DB.startswith('postgresql://'): DB=DB.replace('postgresql://','postgresql+psycopg2://',1)
SECRET=os.getenv('SECRET_KEY','dev-secret-change-me'); ALG='HS256'
ADMINS={x.strip().lower() for x in os.getenv('ADMIN_EMAILS','').split(',') if x.strip()}
engine=create_engine(DB,connect_args={'check_same_thread':False} if DB.startswith('sqlite') else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine); Base=declarative_base(); pwd=CryptContext(schemes=['bcrypt'],deprecated='auto')
class User(Base):
 __tablename__='users'; id=Column(Integer,primary_key=True); name=Column(String(120),nullable=False); email=Column(String(255),unique=True,index=True,nullable=False); password_hash=Column(String(255),nullable=False); referral_code=Column(String(40),unique=True,index=True,nullable=False); referred_by=Column(String(40)); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Income(Base):
 __tablename__='incomes'; id=Column(Integer,primary_key=True); user_id=Column(Integer,index=True); amount=Column(Float); source=Column(String(120)); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Expense(Base):
 __tablename__='expenses'; id=Column(Integer,primary_key=True); user_id=Column(Integer,index=True); amount=Column(Float); category=Column(String(120)); note=Column(Text,default=''); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Activity(Base):
 __tablename__='activities'; id=Column(Integer,primary_key=True); user_id=Column(Integer); action=Column(String(255)); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
Base.metadata.create_all(engine)
class Register(BaseModel): name:str; email:EmailStr; password:str; referral_code:Optional[str]=None
class Login(BaseModel): email:EmailStr; password:str
class IncomeIn(BaseModel): amount:float; source:str
class ExpenseIn(BaseModel): amount:float; category:str; note:str=''
class FeeIn(BaseModel): amount:float; rate:float
class ConvertIn(BaseModel): amount:float; rate:float
app=FastAPI(title='Revenus+'); app.mount('/static',StaticFiles(directory='app/static'),name='static')
def db():
 s=SessionLocal()
 try: yield s
 finally: s.close()
def admin(u): return u.email.lower() in ADMINS
def token(u): return jwt.encode({'sub':str(u.id),'exp':datetime.now(timezone.utc)+timedelta(days=7)},SECRET,algorithm=ALG)
def me(request:Request,s:Session=Depends(db)):
 t=request.cookies.get('access_token')
 if not t: raise HTTPException(401,'Non connecté')
 try: uid=int(jwt.decode(t,SECRET,algorithms=[ALG])['sub'])
 except (JWTError,ValueError,KeyError): raise HTTPException(401,'Session invalide')
 u=s.get(User,uid)
 if not u: raise HTTPException(401,'Utilisateur introuvable')
 return u
def log(s,uid,action): s.add(Activity(user_id=uid,action=action)); s.commit()
@app.get('/')
def home(): return FileResponse('app/static/index.html')
@app.get('/api/health')
def health(): return {'status':'ok','service':'revenus-plus'}
@app.post('/api/auth/register')
def register(d:Register,s:Session=Depends(db)):
 email=d.email.lower()
 if s.query(User).filter_by(email=email).first(): raise HTTPException(400,'Cette adresse e-mail est déjà utilisée.')
 if len(d.password)<6: raise HTTPException(400,'Mot de passe : 6 caractères minimum.')
 ref=None
 if d.referral_code:
  r=s.query(User).filter_by(referral_code=d.referral_code.strip().upper()).first()
  if not r: raise HTTPException(400,'Code de parrainage invalide.')
  ref=r.referral_code
 code='REV'+os.urandom(4).hex().upper()
 u=User(name=d.name.strip(),email=email,password_hash=pwd.hash(d.password),referral_code=code,referred_by=ref); s.add(u); s.commit(); s.refresh(u); log(s,u.id,'Inscription')
 return {'message':'Compte créé','user':{'id':u.id,'name':u.name,'email':u.email,'referral_code':u.referral_code}}
@app.post('/api/auth/login')
def login(d:Login,response:__import__('fastapi').Response,s:Session=Depends(db)):
 u=s.query(User).filter_by(email=d.email.lower()).first()
 if not u or not pwd.verify(d.password,u.password_hash): raise HTTPException(401,'E-mail ou mot de passe incorrect.')
 response.set_cookie('access_token',token(u),httponly=True,secure=True,samesite='lax',max_age=604800); log(s,u.id,'Connexion')
 return {'message':'Connexion réussie','user':{'id':u.id,'name':u.name,'email':u.email,'referral_code':u.referral_code,'admin':admin(u)}}
@app.post('/api/auth/logout')
def logout(response:__import__('fastapi').Response): response.delete_cookie('access_token'); return {'message':'Déconnecté'}
@app.get('/api/me')
def getme(u:User=Depends(me)): return {'id':u.id,'name':u.name,'email':u.email,'referral_code':u.referral_code,'admin':admin(u)}
@app.post('/api/incomes')
def income(d:IncomeIn,u:User=Depends(me),s:Session=Depends(db)):
 if d.amount<=0: raise HTTPException(400,'Montant invalide.')
 s.add(Income(user_id=u.id,amount=d.amount,source=d.source.strip())); s.commit(); log(s,u.id,'Ajout revenu'); return {'message':'Revenu ajouté'}
@app.post('/api/expenses')
def expense(d:ExpenseIn,u:User=Depends(me),s:Session=Depends(db)):
 if d.amount<=0: raise HTTPException(400,'Montant invalide.')
 s.add(Expense(user_id=u.id,amount=d.amount,category=d.category.strip(),note=d.note.strip())); s.commit(); log(s,u.id,'Ajout dépense'); return {'message':'Dépense ajoutée'}
@app.get('/api/dashboard')
def dashboard(u:User=Depends(me),s:Session=Depends(db)):
 inc=s.query(Income).filter_by(user_id=u.id).all(); exp=s.query(Expense).filter_by(user_id=u.id).all(); a=sum(x.amount for x in inc); b=sum(x.amount for x in exp); return {'income':a,'expense':b,'balance':a-b}
@app.post('/api/simulators/fee')
def fee(d:FeeIn):
 if d.amount<0 or d.rate<0: raise HTTPException(400,'Valeurs invalides.')
 f=d.amount*d.rate/100; return {'fee':round(f,2),'total':round(d.amount+f,2)}
@app.post('/api/simulators/convert')
def convert(d:ConvertIn):
 if d.amount<0 or d.rate<0: raise HTTPException(400,'Valeurs invalides.')
 return {'result':round(d.amount*d.rate,2)}
@app.get('/api/admin/stats')
def astats(u:User=Depends(me),s:Session=Depends(db)):
 if not admin(u): raise HTTPException(403,'Accès administrateur refusé.')
 a=sum(x.amount for x in s.query(Income)); b=sum(x.amount for x in s.query(Expense)); return {'users':s.query(User).count(),'income':a,'expense':b,'balance':a-b}
@app.get('/api/admin/users')
def ausers(u:User=Depends(me),s:Session=Depends(db)):
 if not admin(u): raise HTTPException(403,'Accès administrateur refusé.')
 return [{'id':x.id,'name':x.name,'email':x.email,'referral_code':x.referral_code,'created_at':x.created_at.isoformat()} for x in s.query(User).order_by(User.created_at.desc()).all()]
@app.delete('/api/admin/users/{uid}')
def adel(uid:int,u:User=Depends(me),s:Session=Depends(db)):
 if not admin(u): raise HTTPException(403,'Accès administrateur refusé.')
 if uid==u.id: raise HTTPException(400,'Impossible de supprimer le compte connecté.')
 x=s.get(User,uid)
 if not x: raise HTTPException(404,'Utilisateur introuvable.')
 s.query(Income).filter_by(user_id=uid).delete(); s.query(Expense).filter_by(user_id=uid).delete(); s.query(Activity).filter_by(user_id=uid).delete(); s.delete(x); s.commit(); return {'message':'Utilisateur supprimé'}
@app.get('/api/admin/activities')
def activities(u:User=Depends(me),s:Session=Depends(db)):
 if not admin(u): raise HTTPException(403,'Accès administrateur refusé.')
 return [{'user_id':x.user_id,'action':x.action,'created_at':x.created_at.isoformat()} for x in s.query(Activity).order_by(Activity.created_at.desc()).limit(100)]
