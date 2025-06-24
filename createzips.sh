@echo off
echo Creating directories...
mkdir ./source/createtables
mkdir ./source/listusers
mkdir ./source/listgroups
mkdir ./source/listgroupmembership
mkdir ./source/listpermissionsets
mkdir ./source/listprovisionedpermissionsets
mkdir ./source/listaccounts
mkdir ./source/listuseraccountassignments
mkdir ./source/listgroupaccountassignments
mkdir ./source/getiamroles
mkdir ./source/accessanalyzerfindingingestion
mkdir ./source/s3export

rm ./zip/*.zip

echo Creating zip files...

zip -j ./zip/createtables.zip ./source/createtables/lambda_function.py

zip -j ./zip/listusers.zip ./source/listusers/lambda_function.py

zip -j ./zip/listgroups.zip ./source/listgroups/lambda_function.py

zip -j ./zip/listgroupmembership.zip ./source/listgroupmembership/lambda_function.py

zip -j ./zip/listpermissionsets.zip ./source/listpermissionsets/lambda_function.py

zip -j ./zip/listprovisionedpermissionsets.zip ./source/listprovisionedpermissionsets/lambda_function.py

zip -j ./zip/listaccounts.zip ./source/listaccounts/lambda_function.py

zip -j ./zip/listuseraccountassignments.zip ./source/listuseraccountassignments/lambda_function.py

zip -j ./zip/listgroupaccountassignments.zip ./source/listgroupaccountassignments/lambda_function.py

zip -j ./zip/getiamroles.zip ./source/getiamroles/lambda_function.py

zip -j ./zip/accessanalyzerfindingingestion.zip ./source/accessanalyzerfindingingestion/lambda_function.py

zip -j ./zip/s3export.zip ./source/s3export/lambda_function.py

echo All done!
