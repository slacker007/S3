# S3
Open Source Windows Security Event Log Correlation and Analysis Tool

sudo docker run --detach --publish=7474:7474 \
--publish=7687:7687 --publish=7473:7473 \
--volume=$HOME/neo4j/data:/data \
--volume=$HOME/neo4j/logs:/logs neo4j:3.1 \
Open Browser: Navigate to http://localhost:7474/browser \
log in with neo4j as username and neo4j as pw \
set your custom password with database \
#
git clone http://www.github.com/williballenthin/python-evtx \
cd python-evtx/scripts \
python evtx_dump Security.evtx > Security.xml \
#
git clone http://www.github.com/slacker007/s3 \
cd s3 \
python splunksexysix.py --input path/to/your/Security.xml \
#
