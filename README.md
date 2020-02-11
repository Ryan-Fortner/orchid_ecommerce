# orchid_ecommerce
E-commerce site that sells clothing and allows user registration

To run Python Application cd into sql_alch folder and run following commands in terminal: 
------------------------------------------------------------------
| Mac/Linux: | source py3SQLAlchemyEnv/bin/activate                         
------------------------------------------------------------------
| Windows command prompt : | py3SQLAlchemyEnv\Scripts\activate       
------------------------------------------------------------------
| Windows git bash : | source py3SQLAlchemyEnv/Scripts/activate         
------------------------------------------------------------------
(py3SQLAlchemyEnv) pip install flask-sqlalchemy
------------------------------------------------------------------
(py3SQLAlchemyEnv) pip install flask-migrate
------------------------------------------------------------------
(py3SQLAlchemyEnv) flask db migrate
------------------------------------------------------------------
(py3SQLAlchemyEnv) flask db upgrade
------------------------------------------------------------------
