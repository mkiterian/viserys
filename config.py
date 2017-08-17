class Config(object):
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(Config):
    SECRET_KEY = 'asdfh87sf454yhggfd45dererfds22as112'
    SQLALCHEMY_DATABASE_URI = 'postgresql://localhost/viserys'
    # SQLALCHEMY_DATABASE_URI = 'postgres://mjpkpslhyxsugc:c96eb886222059ab00d391a4bb957cd624608e6799383e80997847770a8437fe@ec2-50-19-95-47.compute-1.amazonaws.com:5432/dfp3o42ok4g498'
    JWT_AUTH_URL_RULE = '/api/v1/auth/login'

class TestingConfig(Config):
    SECRET_KEY = '8h87yhggfd45dfds22as'
    TESTING = True
    WTF_CSRF_ENABLED = False
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://'\
        'localhost/try_viserys'

