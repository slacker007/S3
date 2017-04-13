
# S3
Open Source Windows Security Event Log Correlation and Analysis Tool

sudo docker run --detach --publish=7474:7474 \
--publish=7687:7687 --publish=7473:7473 \
--volume=$HOME/neo4j/data:/data \
--volume=$HOME/neo4j/logs:/logs neo4j:3.1 \
Open Browser: Navigate to http://192.168.2.91:7474/browser \ 
log in with neo4j as username and neo4j as pw \
set your custom password with database \

