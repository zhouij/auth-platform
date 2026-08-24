CREATE USER auth_user WITH PASSWORD 'auth_pass';
CREATE USER iam_user WITH PASSWORD 'iam_pass';
CREATE USER resource_user WITH PASSWORD 'resource_pass';
CREATE USER web_user WITH PASSWORD 'web_pass';

CREATE DATABASE authdb OWNER auth_user;
CREATE DATABASE iamdb OWNER iam_user;
CREATE DATABASE resourcedb OWNER resource_user;
CREATE DATABASE webdb OWNER web_user;
