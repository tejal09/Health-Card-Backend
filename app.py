import os
import upload
from flask import Flask, jsonify, request, json, redirect, send_from_directory
from flask_pymongo  import PyMongo
from bson.json_util import dumps
import json
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash,check_password_hash
from flask_cors import CORS, cross_origin
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import urllib.request
from werkzeug.utils import secure_filename



app=Flask(__name__)

app.config['MONGO_URI']="mongodb://localhost:27017/test123"
app.config['JWT_SECRET_KEY'] = "secretkey"

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)
UPLOAD_FOLDER = 'C:/Users/Blaxtation/Desktop/backend/uploads/'

@app.route('/<path:path>', methods=['GET'])
def static_proxy(path):
  return send_from_directory('./', path)


###########################################################################################
########################            USER API             #################################

########################       LOGIN OF USERS      #################################
@app.route('/api/user/login', methods=['POST'])
def loginUser():
    users = mongo.db.users
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
                'user_id': str(response['_id']),
			    'first_name': response['first_name'],
				'last_name': response['last_name'],
				'email': response['email'],
                'age' : response['age'],
                'gender' : response['gender'], 
                'created' : response['created'], 
                'father_name': response['father_name'],
                'mother_name': response['mother_name'],
                'contact_number': response['contact_number'],
                'emergency_contact_number': response['emergency_contact_number'],
                'blood_group': response['blood_group'],
                'dob': response['dob'],
                'profile_photo': response['profile_photo'],
                'marital_status': response['marital_status'],
                'aadhar_number': response['aadhar_number'],
                'street': response['address']['street'],
                'city': response['address']['city'],
                'state': response['address']['state'],
                'pincode': response['address']['pincode'],
                'landmark': response['address']['landmark']
                
            })
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid Email or Password"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result

#######################         USER DETAILS WITH FULL DETAILS          ###########################################

@app.route('/api/user/<id>',methods=['GET'])
def view_details(id):
    user = mongo.db.users
    field = user.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'user_id':str(field['_id']),
                'first_name':field['first_name'],
                'last_name':field['last_name'],
                'email':field['email'],
                'age':field['age'],
                'gender':field['gender'],
                'father_name':field['father_name'],
                'mother_name':field['mother_name'],
                'contact_number':field['contact_number'],        
                'emergency_contact_number':field['emergency_contact_number'],
                'profile_photo':field['profile_photo'],
                'blood_group': field['blood_group'],
                'dob':field['dob'],
                'marital_status':field['marital_status'],
                'aadhar_number':field['aadhar_number'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                    }

    else:
        output = "No such name"
    print(output)        
    return jsonify(output)    


#**********************************************************************************************************************************************************
#**********************************************************************************************************************************************************
########################            ADMIN API             #################################

########################       LOGIN OF ADMIN      #################################
@app.route('/api/login', methods=['POST'])
def loginAdmin():
    users = mongo.db.admin
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'first_name': response['first_name'],
				'last_name': response['last_name'],
				'email': response['email']}
				)
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid Email or Pssword"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result



######################## ADMIN WILL REGISTER - REGISTRATION OF USERS USER REGISTRATION #################################
@app.route('/api/register', methods=['POST'])
def registerUser():
    # check if the post request has the file part
    if 'profile_photo' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['profile_photo']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # dt = str(datetime.utcnow())
        # filenameplusdate = str(dt+filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        # def savefilenametodatabase():
        #     location = mongo.db.users

        resp.status_code = 201

    users = mongo.db.users

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    gender = request.form['gender']
    age = request.form['age']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    father_name = request.form['father_name']
    mother_name = request.form['mother_name']
    blood_group = request.form['blood_group']
    marital_status = request.form['marital_status']
    aadhar_number = request.form['aadhar_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    dob = request.form['dob']
    
    created = datetime.utcnow()
    print(created)

    user_id = users.insert_one({
        'first_name' : first_name, 
        'last_name' : last_name, 
        'email' : email, 
        'password' : password,
        'age' : age,
        'gender' : gender, 
        'created' : created, 
        'father_name':father_name,
        'mother_name':mother_name,
        'contact_number':contact_number,
        'emergency_contact_number':emergency_contact_number,
        'profile_photo':save_filename,
        'blood_group': blood_group,
        'dob': dob,
        'marital_status':marital_status,
        'aadhar_number':aadhar_number,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    # new_user = users.find_one({'_id' : user_id})

    # result = {'email' : new_user['email'] + ' registered'}
    # print('result is ',result)
    return jsonify({'result' : 'user saved'})
	



#**********************************************************************************************************************************************************
#**********************************************************************************************************************************************************
########################            CLINICS  API            ##########################

########################       REGISTRATION OF CLINICS      #################################


ALLOWED_EXTENSIONS_CLINICS = set(['pdf'])

def allowed_file_for_clinics(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_CLINICS

@app.route('/api/clinic/register', methods=['POST'])
def registerClinic():
    # check if the post request has the file part
    if 'clinic_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['clinic_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file_for_clinics(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/clinicsregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/clinicregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201

    clinic = mongo.db.clinics

    clinic_name = request.form['clinic_name']
    license_number = request.form['license_number']
    established_date = request.form['established_date']
    doctor_name = request.form['doctor_name']
    qualification = request.form['qualification']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    gender = request.form['gender']
    age = request.form['age']
    dob = request.form['dob']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    created = datetime.utcnow()
    print(created)

    user_id = clinic.insert_one({
        'clinic_name' : clinic_name, 
        'license_number' : license_number, 
        'established_date' : established_date, 
        'doctor_name' : doctor_name, 
        'qualification' : qualification, 
        'email' : email, 
        'password' : password,
        'age' : age,
        'gender' : gender,
        'dob': dob,
        'created' : created, 
        'contact_number':contact_number,
        'emergency_contact_number':emergency_contact_number,
        'clinic_document':save_filename,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})



#########################    CLINIC LOGIN       ##########################

@app.route('/api/clinic/login', methods=['POST'])
def loginClinic():
    users = mongo.db.clinics
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})
    print(response)
    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {'_id': str(response['_id'])}, expires_delta=None)
            result = jsonify({"token":access_token, "_id": str(response['_id']), 'clinic_name':response['clinic_name'] })
        else:
            result = jsonify({"error":"Invalid Email or Password"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result


##################### GETTING ALL THE CLINICS NAMES ONLY  ##########################
@app.route('/api/clinics/clinic-list', methods=['GET'])
def get_all_clinics_list():
    clinic = mongo.db.clinics
    result = []
    for field in clinic.find():
        result.append({'_id': str(field['_id']), 'clinic_name':field['clinic_name']})
    # *resp = dumps(users)
    return jsonify(result)    
	


##################### GETTING ALL THE CLINIC DETAILS   ##########################
@app.route('/api/clinic/<id>',methods=['GET'])
def view_clinic_details(id):
    clinic = mongo.db.clinics
    field = clinic.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'clinic_name':field['clinic_name'], 
                'license_number' : field['license_number'], 
                'established_date' : field['established_date'], 
                'doctor_name' : field['doctor_name'], 
                'qualification' :field ['qualification'], 
                'email' :field['email'], 
                'age' : field['age'],
                'gender' :field['gender'],
                'dob': field['dob'],
                'created' : field['created'], 
                'contact_number':field['contact_number'],
                'emergency_contact_number':field['emergency_contact_number'],
                'clinic_document':field['clinic_document'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                }

    else:
        output = "No such Clinic Found"
    print(output)
    return jsonify(output)


#**********************************************************************************************************************************************************
#**********************************************************************************************************************************************************
########################            DOCTOR API            #################################


########################    REGISTRATION OF NEW DOCTOR    #################################

ALLOWED_EXTENSIONS_DOCTOR_DOCUMENT = set(['pdf'])

def allowed_file_for_doctor_document(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_DOCTOR_DOCUMENT
    
ALLOWED_EXTENSIONS_DOCTOR_PHOTO = set(['jpeg, jpg, png'])

def allowed_file_for_doctor_photo(filenameofphoto):
	return '.' in filenameofphoto and filenameofphoto.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_DOCTOR_PHOTO

@app.route('/api/doctor/register', methods=['POST'])
def registerDoctor():
    
    # check if the post request has the file part


    if 'doctor_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['doctor_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    
    if file and allowed_file_for_doctor_document(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/doctorsregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/doctorsregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201
    # return uploadPhoto(photo_save_filename)


   


    

    users = mongo.db.doctors

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    gender = request.form['gender']
    license_number = request.form['license_number']
    dob = request.form['dob']
    age = request.form['age']
    qualification = request.form['qualification']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    DocumentToUpload = save_filename
    address_landmark = request.form['landmark']


    
    
    created = datetime.utcnow()

    user_id = users.insert({
	'first_name' : first_name, 
	'last_name' : last_name, 
	'email' : email, 
	'password' : password,
    'age' : age,
    'gender' : gender, 
	'created' : created, 
    'contact_number':contact_number,
    'emergency_contact_number':emergency_contact_number,
    'qualification':qualification,
    'dob':dob,
    # 'profile_photo': PhotoToUpload,
    'doctor_document': DocumentToUpload,
    'license_number':license_number,
    'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})
	

#####################           LOGIN OF DOCTOR                ##################################

@app.route('/api/doctor/login', methods=['POST'])
def loginDoctor():
    users = mongo.db.doctors
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})
    print(response)
    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {'_id': str(response['_id'])}, expires_delta=None)
            result = jsonify({"token":access_token, "_id": str(response['_id']), 'doctor_name':response['first_name'] })
        else:
            result = jsonify({"error":"Invalid Email or Password"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result


##################### GETTING ALL THE DOCTORS ONLY NAMES ##########################
@app.route('/api/doctor/doctor-list', methods=['GET'])
def get_all_doctor_list():
    user = mongo.db.doctors
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'first_name':field['first_name'], 'last_name':field['last_name']})
    # *resp = dumps(users)
    return jsonify(result)


######################## GETTING ALL DOCTOR DETAILS  ####################
@app.route('/api/doctor/<id>',methods=['GET'])
def view_doctor_details(id):
    doctor = mongo.db.doctors
    field = doctor.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'first_name':field['first_name'], 
                'last_name' : field['last_name'], 
                'email' : field['email'], 
                'dob' : field['dob'], 
                'license_number' : field['license_number'], 
                'gender' : field['gender'], 
                'qualification' : field['qualification'],
                'contact_number':field['contact_number'],
                'emergency_contact_number':field['emergency_contact_number'],
                'doctor_document':field['doctor_document'],
                'profile_photo':field['profile_photo'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                }

    else:
        output = "No such Doctor Found"
    print(output)
    return jsonify(output)










###########################################################################################
########################          HOSPITAL API            #################################


########################    REGISTRATION OF NEW HOSPITAL    #################################
@app.route('/api/hospital/register', methods=['POST'])
def registerHospital():
    # check if the post request has the file part
    if 'hospital_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['hospital_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file_for_clinics(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/hospitalsregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/hospitalsregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201

    hospital = mongo.db.hospitals

    hospital_name = request.form['hospital_name']
    license_number = request.form['license_number']
    established_date = request.form['established_date']
    email = request.form['email']
    owner_name = request.form['owner_name']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    created = datetime.utcnow()
    print(created)

    user_id = hospital.insert_one({
        'hospital_name' : hospital_name, 
        'license_number' : license_number, 
        'established_date' : established_date, 
        'email' : email, 
        'owner_name':owner_name,
        'password' : password,
        'created' : created, 
        'contact_number':contact_number,
        'emergency_contact_number':emergency_contact_number,
        'hospital_document':save_filename,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})
    

##################### LOGIN OF HOSPITAL ##################################

@app.route('/api/hospital/login', methods=['POST'])
def loginHospital():
    users = mongo.db.hospitals
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'hospital_name': response['hospital_name'],
				'email': response['email']}
				)
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid Email or Password"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result


##################### GETTING ALL THE HOSPITAL ONLY NAMES ##########################
@app.route('/api/hospital/list', methods=['GET'])
def get_all_hospital_list():
    user = mongo.db.hospitals
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'hospital_name':field['hospital_name']})
    # *resp = dumps(users)
    return jsonify(result)





##################### GETTING ALL THE HOSPITAL DETAILS   ##########################
@app.route('/api/hospital/<id>',methods=['GET'])
def view_hospital_details(id):
    hospital = mongo.db.hospitals
    field = hospital.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'hospital_name':field['hospital_name'], 
                'license_number' : field['license_number'], 
                'established_date' : field['established_date'], 
                'created' : field['created'], 
                'email' : field['email'], 
                'owner_name' : field['owner_name'], 
                'contact_number':field['contact_number'],
                'emergency_contact_number':field['emergency_contact_number'],
                'hospital_document':field['hospital_document'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                }

    else:
        output = "No such Clinic Found"
    print(output)
    return jsonify(output)









###########################################################################################
########################          LABORATORY API            #################################


########################    REGISTRATION OF NEW LABORATORY    #################################
@app.route('/api/laboratory/register', methods=['POST'])
def registerLaboratory():
    # check if the post request has the file part
    if 'laboratory_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['laboratory_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file_for_clinics(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/laboratoryregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/laboratoryregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201

    laboratory = mongo.db.laboratory

    laboratory_name = request.form['laboratory_name']
    license_number = request.form['license_number']
    established_date = request.form['established_date']
    email = request.form['email']
    owner_name = request.form['owner_name']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    created = datetime.utcnow()
    print(created)

    user_id = laboratory.insert_one({
        'laboratory_name' : laboratory_name, 
        'license_number' : license_number, 
        'established_date' : established_date, 
        'email' : email, 
        'owner_name':owner_name,
        'password' : password,
        'created' : created, 
        'contact_number':contact_number,
        'emergency_contact_number':emergency_contact_number,
        'laboratory_document':save_filename,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})
    

##################### LOGIN OF LABORATORY ##################################

@app.route('/api/laboratory/login', methods=['POST'])
def loginLaboratory():
    users = mongo.db.laboratory
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'laboratory_name': response['laboratory_name'],
				'email': response['email']}
				)
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid Email or Password"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result


##################### GETTING ALL THE LABORATORY ONLY NAMES ##########################
@app.route('/api/laboratory/laboratory-list', methods=['GET'])
def get_all_laboratory_list():
    user = mongo.db.laboratory
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'laboratory_name':field['laboratory_name']})
    # *resp = dumps(users)
    print(result)
    return jsonify(result)





##################### GETTING ALL THE LABORATORY DETAILS   ##########################
@app.route('/api/laboratory/<id>',methods=['GET'])
def view_laboratory_details(id):
    onelaboratory = mongo.db.laboratory
    field = onelaboratory.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'laboratory_name':field['laboratory_name'], 
                'license_number' : field['license_number'], 
                'established_date' : field['established_date'], 
                'created' : field['created'], 
                'email' : field['email'], 
                'owner_name' : field['owner_name'], 
                'contact_number':field['contact_number'],
                'emergency_contact_number':field['emergency_contact_number'],
                'laboratory_document':field['laboratory_document'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                }

    else:
        output = "No such Clinic Found"
    print(output)
    return jsonify(output)











###########################################################################################
########################          MEDICAL API            #################################


########################    REGISTRATION OF NEW MEDICAL    #################################
@app.route('/api/medical/register', methods=['POST'])
def registermedical():
    # check if the post request has the file part
    if 'medical_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['medical_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file_for_clinics(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/medicalregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/medicalregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201

    medical = mongo.db.medicals

    medical_name = request.form['medical_name']
    license_number = request.form['license_number']
    established_date = request.form['established_date']
    email = request.form['email']
    owner_name = request.form['owner_name']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    created = datetime.utcnow()
    print(created)

    user_id = medical.insert_one({
        'medical_name' : medical_name, 
        'license_number' : license_number, 
        'established_date' : established_date, 
        'email' : email, 
        'owner_name':owner_name,
        'password' : password,
        'created' : created, 
        'contact_number':contact_number,
        'emergency_contact_number':emergency_contact_number,
        'medical_document':save_filename,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})
    

##################### LOGIN OF MEDICAL ##################################

@app.route('/api/medical/login', methods=['POST'])
def loginmedical():
    users = mongo.db.medicals
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'medical_name': response['medical_name'],
				'email': response['email']}
				)
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid Email or Password"})            
    else:
        result = jsonify({"result":"Invalid Email or Password"})
    return result


##################### GETTING ALL THE MEDICAL ONLY NAMES ##########################
@app.route('/api/medical/list', methods=['GET'])
def get_all_medical_list():
    user = mongo.db.medicals
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'medical_name':field['medical_name']})
    # *resp = dumps(users)
    print(result)
    return jsonify(result)





##################### GETTING ALL THE MEDICAL DETAILS   ##########################
@app.route('/api/medical/<id>',methods=['GET'])
def view_medical_details(id):
    medical = mongo.db.medicals
    field = medical.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'medical_name':field['medical_name'], 
                'license_number' : field['license_number'], 
                'established_date' : field['established_date'], 
                'created' : field['created'], 
                'email' : field['email'], 
                'owner_name' : field['owner_name'], 
                'contact_number':field['contact_number'],
                'emergency_contact_number':field['emergency_contact_number'],
                'medical_document':field['medical_document'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                }

    else:
        output = "No such Clinic Found"
    print(output)
    return jsonify(output)
















##################### GETTING ALL THE USERS ONLY NAMES ##########################
@app.route('/api/users/', methods=['GET'])
def get_all_users():
    user = mongo.db.users
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'first_name':field['first_name'], 'last_name':field['last_name']})
    # *resp = dumps(users)
    print(result)
    return jsonify(result)


@app.route('/api/users/emails/', methods=['GET'])
def get_all_users_email():
    user = mongo.db.users
    result = []
    for field in user.find():
        result.append({'email':field['email']})
    # *resp = dumps(users)
    return jsonify(result)

    # #adding new user
# @app.route('/api/users', methods=['POST'])
# def add_user():
  
#     user = mongo.db.user
#     name = request.get_json()['name']
#     user_id = user.insert({'name': name})
#     new_user = user.find_one({'_id': user_id})

#     result = {'name': new_user['name']}
#     return jsonify({'result': result})




#updating by <id> details
@app.route('/api/user/<id>', methods=['PUT'])
def userss(id):
    user=mongo.db.users
    # case_title=request.get_json()['case_title']
    user.find_one_and_update({'_id': ObjectId(id)}, {'$push':{'cases':{'_id':ObjectId(),"case_name":"Case Blah BLah"}}},upsert=False)
    # new_user = user.find_one({'_id': ObjectId(id)})
    # result = {'name': new_user['name']}
    return jsonify({'result': "Success"})


# Deleting any user by ID
@app.route('/api/user/<id>',methods=['DELETE'])
def delete_user(id):
    user=mongo.db.user
    response = user.delete_one({'_id': ObjectId(id)})
    if response.deleted_count == 1:
        result= {'message':'record deleted'}
    else:
        result= {'message':'No record deleted'}

    return jsonify({'result': result})


# @app.route('/api/user/cases/<id>',methods=['GET'])
# def view_cases(id):
#     user = mongo.db.users
#     # result = []
#     result = user.find_one({'_id':ObjectId(id)},{'cases': 1,'_id': 0, 'cases.disease': 1, 'cases._id':str('_id')})  ##  result.append({'_id': str(field['_id']),
#     # print(result)
#     # return jsonify(result)

#     resp = json.loads(dumps(result))
#     print(resp)
#     return jsonify(resp)

############## ADDING A NEW CASE ##################
#updating by <id> details
@app.route('/api/user/<id>', methods=['PUT'])
def add_new_case_to_user(id):
    user=mongo.db.users
    # case_title=request.get_json()['case_title']
    user.find_one_and_update({'_id': ObjectId(id)}, {'$push':{'cases':{'_id':ObjectId(),"case_name":"Case Blah BLah"}}},upsert=False)
    # new_user = user.find_one({'_id': ObjectId(id)})
    # result = {'name': new_user['name']}
    return jsonify({'result': "Success"})




############### alll cases of one user ########################

@app.route('/api/user/cases/<id>',methods=['GET'])
def view_cases(id):
    user = mongo.db.users
    result = []

    for field in user.find_one({'_id':ObjectId(id)},{'cases': 1,'_id': 0, 'cases.disease_name': 1, 'cases._id':1})['cases']:
        result.append({'_id':str(field['_id']), 'disease_name':field['disease_name']})
    print(result)
    return jsonify(result)


#################### only one case
@app.route('/api/user/cases/case-details/<id>',methods=['GET'])
def view_case_detail(id):
    user = mongo.db.users
    # result = []
    result = user.find_one({'cases._id':ObjectId(id)},{"cases.$.": 1, '_id': 0})['cases']
        # output = {'disease_name':field['disease_name'],'disease_observation':field['disease_observation']}
    result = result[0]
    resp = json.loads(dumps(result))

    print(resp)
    return jsonify(resp)
    # result = user.find_one({'cases._id':ObjectId(id)},{"cases.$.": 1, '_id': 0})['cases']

    # resp = json.loads(dumps(result))
    # print(resp)
    # return jsonify(resp)

# @app.route('/api/user/cases/<id>',methods=['GET'])
# def view_cases(id):
#     user = mongo.db.users
#     result = []
#     result = user.find_one({ 
#         "$and": [
#             {"_id": ObjectId(id)}, 
#             {"cases": {"$exists": {"case_name":True}}}
#         ] 
#         })
    # for field in user.find({'cases':"case_name"}):
        # result.append({'_id':ObjectId(id), 'case_name':field['case_name']})
    # resp = json.loads(dumps(result))
    # print(resp)
    # return jsonify(resp)



# @app.route('/api/cases/')
#     cases= mongo.db.cases
#     casenumb= request.get_json('')


    # user=mongo.db.user
    # result = []
    # for field in user.find_one({'_id':ObjectId(id)}):
    #     result.append({ 'name':field['name'], 'city':field['city']})
    
    # return jsonify(result)
 



 ##########################################################################################################

 #######################          UPLOAD         ##########################




ALLOWED_EXTENSIONS = set(['pdf'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/user/cases/upload/<id>', methods=['POST'])
def uploadLabReportToPatientDetails(id):
 # check if the post request has the file part
    if 'patient_lab_report' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['patient_lab_report']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # dt = str(datetime.utcnow())
        # filenameplusdate = str(dt+filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/labreports', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/labreports/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        # def savefilenametodatabase():
        #     location = mongo.db.users

        resp.status_code = 201
    user = mongo.db.users    
    # casessss = casess.insert_one(abc)
    resp = user.find_one_and_update({'cases._id': ObjectId(id)}, 
                                    {'$push':
                                            {'cases.id':
                                                        {'patient_lab_report':save_filename}
                                            }
                                    },upsert=False)
    
    # result = user.find_one_and_update({'cases._id':ObjectId(id)},{"cases.$.": 1, '_id': 0})['cases']
        # output = {'disease_name':field['disease_name'],'disease_observation':field['disease_observation']}
    # result = result[0]
    result = json.loads(dumps(resp))

    print(result)
    return jsonify(result)

################  DIFFERENT USERS COUNT FOR ADMIN DASHBOARD #####################33
@app.route('/api/count', methods=['GET'])
def get_all_counts():
    result = []
    users_count = mongo.db.users.count()
    doctors_count = mongo.db.doctors.count()
    hospitals_count = mongo.db.hospitals.count()
    clinics_count = mongo.db.clinics.count()
    medicals_count = mongo.db.medicals.count()
    laboratory_count = mongo.db.laboratory.count()

    result={'users_count':users_count,
            'hospitals_count':hospitals_count,
            'doctors_count':doctors_count,
            'clinics_count':clinics_count,
            'medicals_count':medicals_count,
            'laboratory_count':laboratory_count}
    
    return jsonify(result)


@app.route('/api/add-cases/<id>',methods=['PUT'])
def save_case(id):
    print(request.get_json())

    casess = mongo.db.users
    
    abc = request.get_json()
    abc["_id"] = ObjectId()
    # casessss = casess.insert_one(abc)
    updated = casess.find_one_and_update({'_id': ObjectId(id)}, {'$push':{'cases':abc}},upsert=False)
    

    print(updated)
    return jsonify({'result':"SUCCESSFULLY ADDED A NEW CASE"})


    #updating by <id> details
# @app.route('/api/user/<id>', methods=['PUT'])
# def userss(id):
#     user=mongo.db.users
#     # case_title=request.get_json()['case_title']
#     user.find_one_and_update({'_id': ObjectId(id)}, {'$push':{'cases':{'_id':ObjectId(),"case_name":"Case Blah BLah"}}},upsert=False)
#     # new_user = user.find_one({'_id': ObjectId(id)})
#     # result = {'name': new_user['name']}
#     return jsonify({'result': "Success"})

    


@app.errorhandler(404)
def not_found(error=None):
    message = {
        'status':404,
        'message':'Not found blah blah NOT WORKING' + request.url
    }
    resp = jsonify(message)

    resp.status_code = 404

    return resp

if __name__ == "__main__":
    app.run(debug=True)
