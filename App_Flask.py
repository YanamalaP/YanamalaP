import sqlite3
import traceback
import uuid
import jwt
import datetime
from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash,check_password_hash
#from flask_sqlalchemy import SQLAlchemy
from functools import wraps
# create and initialize a new Flask app
app = Flask("MyApp")

app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'sqlite://///home/manthantrivedi/Documents/Bacancy/bacancy_blogs/flask_auth/myflaskproject/bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

#db = SQLAlchemy(app)

def get_db_connection():
    """creates data base connection"""
    db = sqlite3.connect('data.db')
    db.row_factory = dict_factory
    curser = db.cursor()
    table = "CREATE table IF NOT EXISTS tbl_router(Sapid, Hostname, Loopback, Mac_address, is_deleted TEXT DEFAULT 0)"
    curser.execute(table)

    table_user = "CREATE table IF NOT EXISTS tbl_users(name, password, public_id)"
    curser.execute(table_user)

    return db

def dict_factory(curser, row):
    d = {}
    for index, col in enumerate(curser.description):
        d[col[0]] = row[index]
    return d

@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    sql = f"""INSERT INTO tbl_users(name, password, public_id) 
                VALUES("{data['name']}", "{hashed_password}","{str(uuid.uuid4())}")"""
    db = get_db_connection()
    curser = db.cursor()
    curser.execute(sql)
    db.commit()
    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authentication': 'login required"'})

    sql = f"""SELECT name, password, public_id FROM tbl_users where name='{auth.username}'"""
    cursor = get_db_connection().cursor()
    cursor.execute(sql)
    user_info = cursor.fetchone()
    if not user_info:
        make_response('user not exist in db', 401, {'Authentication': 'signup required"'})

    # Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user_info["password"], auth.password):
        token = jwt.encode(
            {'public_id': user_info["public_id"], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=4005)},
            app.config['SECRET_KEY'], "HS256")

        return jsonify({'token': token})

    return make_response('could not verify', 401, {'Authentication': '"login required"'})

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            sql = f"""SELECT name, public_id FROM tbl_users where public_id="{data['public_id']}" """
            cursor = get_db_connection().cursor()
            cursor.execute(sql)
            user_info = cursor.fetchone()
            if not user_info:
                return jsonify({'message': 'token is invalid'})
        except:
            return jsonify({'message': 'token is invalid'})

        return f(user_info, *args, **kwargs)

    return decorator


@app.route('/add', methods=['POST'])
@token_required
def add_router(current_user, *args, **kwargs):
    try:
        _json = request.args
        _Sapid = _json.get('Sapid')
        _Host = _json.get('Hostname')
        _Loop = _json.get('Loopback')
        _Mac_address = _json.get('Mac_address')
        # validate the received values

        if request.method == 'POST':
            sql = f"INSERT INTO tbl_router(Sapid, Hostname, Loopback, Mac_address) VALUES('{_Sapid}', '{_Host}','{_Loop}', '{_Mac_address}')"
            db = get_db_connection()
            curser = db.cursor()
            curser.execute(sql)
            db.commit()
            resp = jsonify('Router added successfully')
            resp.status_code = 200
            return resp
        else:
            return not_found()
    except Exception as error:
        resp = jsonify('Router not added successfully '+str(traceback.format_exc()))
        resp.status_code = 500
        return resp


@app.route('/routers')
@token_required
def get_all_routers(current_user, *args, **kwargs): #get all router details
    try:
        db = get_db_connection()
        curser = db.cursor()
        #curser.execute(f"SELECT Sapid, Hostname, Loopback, Mac_address, is_deleted FROM tbl_router where is_deleted in (0,1)")
        curser.execute(f"SELECT Sapid, Hostname, Loopback, Mac_address, is_deleted FROM tbl_router where is_deleted = 0")
        rows = curser.fetchall()
        resp = jsonify(rows)
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        curser.close()
        db.close()


@app.route('/router/<int:id>')
@token_required
def get_router(current_user, id, *args, **kwargs):
    try:
        db = get_db_connection()
        curser = db.cursor()
        curser.execute(f"SELECT Sapid, Hostname, Loopback, Mac_address FROM tbl_router WHERE Sapid ='{id}'")
        rows = curser.fetchone()
        resp = jsonify(rows)
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        curser.close()
        db.close()



@app.route('/update/<int:id>', methods = ['PUT'])
@token_required
def update_router(current_user, id, *args, **kwargs):
    db = get_db_connection()
    curser = db.cursor()
    try:
        _json = request.args
        sql = "UPDATE tbl_router SET "
        for key, val in _json.items():
            sql += f" {key}='{val}' "

        sql += " WHERE Sapid = '{id}'".format(id=str(id))

        # _Sapid = _json.get('Sapid')
        # _Hostname = _json.get('Hostname')
        # _Loopback = _json.get('Loopback')
        # _Mac_address = _json.get('Mac_address')

        # validate the received values


        if request.method == 'PUT':
            curser.execute(sql)
            db.commit()
            resp = jsonify('Router updated successfully')
            resp.status_code = 200
            return resp
        else:
            return not_found()
    except Exception as e:
        print(e)
        resp = jsonify('Router not added successfully ' + str(traceback.format_exc()))
        resp.status_code = 500
        return resp
    finally:
        db.close()


@app.route('/delete/<int:id>', methods = ['DELETE'])
@token_required
def delete_router(current_user,id,*args, **kwargs):
    try:
        db = get_db_connection()
        curser = db.cursor()
        curser.execute(f"Update tbl_router set is_deleted=1 WHERE Sapid ='{id}'")
        db.commit()
        resp = jsonify("Router Deleted successfully")
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        curser.close()
        db.close()


@app.route('/delete/all', methods = ['DELETE'])
@token_required
def delete_all_routers(current_user,*args, **kwargs):
    try:
        db = get_db_connection()
        curser = db.cursor()
        curser.execute(f"DELETE FROM tbl_router")
        db.commit()
        resp = jsonify("Deleted all routers successfully")
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        curser.close()
        db.close()


"""@app.route('/router/<Sapid>', methods=['DELETE'])
#@token_required
def soft_delete_router(current_user, Sapid):
    route = routers.query.filter_by(id=book_id, user_id=current_user.id).first()
    if not router:
        return jsonify({'message': 'router does not exist'})

    db.session.delete(router)
    db.session.commit()
    return jsonify({'message': 'router deleted'})
"""
@app.errorhandler(404)
def not_found(error = None):
    message = {
        'status' : 404,
        'message' : 'Not Found: '+request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

if __name__ == '__main__':
    app.run(debug = True)