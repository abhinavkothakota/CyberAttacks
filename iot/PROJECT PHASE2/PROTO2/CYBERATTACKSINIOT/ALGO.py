import joblib
model = joblib.load('randomforest_trained.pkl')
M=joblib.load('model.pkl')
print(type(model))
print(type(M))

