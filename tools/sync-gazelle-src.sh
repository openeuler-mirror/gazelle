#!/bin/bash

##########################################################################################

# How to use it?

# 1. fork gazelle_1 from src-openeuler/gazelle. The name can be specified with FORK_TAR;
# 2. COMMIT_ID is a committrf hash record from openeuler/gazelle (this repository);
# 3. TARGET_BRANCH is a branch from src-openeuler/gazelle;
# 4. USER/EMAIL will be autimatically obtailed from  the git configuration;

# Example Usage: 
# > COMMIT_ID="123456789" TARGET_BRANCH="openEuler-20.03-LTS-SP1" bash tools/sync-gazelle-src.sh

##########################################################################################

if [ -z "$COMMIT_ID" ];then
	COMMIT_ID='HEAD'
fi
if [ -z "$TARGET_BRANCH" ];then
	TARGET_BRANCH='master'
fi
if [ -z "$FORK_TAR" ];then
	FORK_TAR='gazelle_1'
fi
if [ -z "$USER" ];then
	USER=$(git config user.name)
fi
if [ -z "$EMAIL" ];then
	EMAIL=$(git config user.email)
fi
specfile="gazelle.spec"

echo $COMMIT_ID $TARGET_BRANCH $FORK_TAR $USER $EMAIL

workdir=$(pwd)
patchname=$(git format-patch -1 $COMMIT_ID | tail -n1)
gitmsg=$(git log --pretty=format:"%s" -1 HEAD | sed -e 's/^![0-9]* //g')
echo $patchname

cd ..
if [ ! -d "$FORK_TAR" ];then
	git clone https://gitee.com/${USER}/${FORK_TAR}.git
	if [ $? -ne 0 ];then
		echo "Invail git fork dir!"
		exit 1;
	fi
fi
cd ${FORK_TAR}
git clean -dfx
git checkout .
git checkout master
git branch -d $TARGET_BRANCH
git checkout -b $TARGET_BRANCH origin/$TARGET_BRANCH
patchnum=$(ls ./*.patch | wc -l)
let patchnum+=1
let Patchnum=9000+$patchnum
patchnum=$(printf "%04d\n" $patchnum)
new_patchname=$(echo $patchname | sed -e "s/^0001-/${patchnum}-/g")

echo $new_patchname

#modify release num in spec file
release=$(grep '^Release:' gazelle.spec | awk '{print $2}')
release_line=$(grep -n '^Release:' gazelle.spec | cut -f1 -d':')
let release+=1
sed -i "${release_line}s/[0-9]*$/${release}/g" ${specfile}

#add Patch in spec file
patch_line=$(grep -n '^Patch' gazelle.spec | tail -n1 | cut -f1 -d':')
sed -i "${patch_line} aPatch${Patchnum}:     ${new_patchname}" ${specfile}

#add changelog in spec file
changelog_line=$(grep -n '^%changelog' gazelle.spec | cut -f1 -d':')
changelog_data=$(date | awk '{print $1,$2,$3,$6}')
changelog_version=$(grep '^Version' gazelle.spec | awk '{print $2}')

sed -i "${changelog_line} G" ${specfile}
sed -i "${changelog_line} a- ${gitmsg}" ${specfile}
sed -i "${changelog_line} a* ${changelog_data} ${USER} <${EMAIL}> - ${changelog_version}-${release}" ${specfile}

mv ${workdir}/${patchname} ./${new_patchname}

#verify patch apply
rm -rf ./rpmbuild/SOURCES/
mkdir -p ./rpmbuild/SOURCES/
cp ./* ./rpmbuild/SOURCES/
rpmbuild -bp ${specfile} -D "%_topdir $(pwd)/rpmbuild/"

if [ $? -ne 0 ];then
	echo "patch apply failed, rej file saved in ./rpmbuild/BUILD!"
	exit 1
fi	

rm -rf ./rpmbuild/
git add -A
git commit -m "sync ${gitmsg}"
git push -f origin $TARGET_BRANCH

cd $workdir
