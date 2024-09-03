#!/bin/bash

##########################################################################################

# How to use it?

# 1. fork gazelle_1 from src-openeuler/gazelle. The name can be specified with FORK_TAR;
# 2. COMMIT_ID is a committrf hash record from openeuler/gazelle (this repository). 
#    Multiple committrf hash records should be separated by spaces;
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
for commitid in ${COMMIT_ID};do
	cd ${workdir}
	patchname=$(git format-patch -1 ${commitid} | tail -n1)
	if [ $? -ne 0 ];then
		echo "invaild commitid $commitid"
		exit 1
	fi
	gitmsg=$(git log --pretty=format:"%s" -1 $commitid | sed -e 's/^![0-9]* //g')
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
	if [ -z "$done_once" ];then
		git clean -dfx
		git checkout .
		git checkout master
		git branch -d $TARGET_BRANCH
		git checkout -b $TARGET_BRANCH origin/$TARGET_BRANCH
		git pull https://gitee.com/src-openeuler/gazelle.git $TARGET_BRANCH
	fi

        #get patchnum from spec file.
        patchnum=$(grep -o "Patch[0-9]\+" *.spec | tail -n 1 | awk -Fh '{print $2}' | awk '{print $1 - 9000}')
        if [ -z $patchnum ];then
            #there is no patch in spec file. get patch by conunt patches in dir. 
	    patchnum=$(ls ./*.patch | wc -l)
        fi
        let patchnum+=1
        let Patchnum=9000+$patchnum
        patchnum=$(printf "%04d\n" $patchnum)
	new_patchname=$(echo $patchname | sed -e "s/^0001-/${patchnum}-/g")

	echo $new_patchname

	#modify release num in spec file
	release=$(grep '^Release:' gazelle.spec | awk '{print $2}')
	release_line=$(grep -n '^Release:' gazelle.spec | cut -f1 -d':')
	let release+=1

	#add Patch in spec file
	patch_line=$(grep -n '^Patch' gazelle.spec | tail -n1 | cut -f1 -d':')
	sed -i "${patch_line} aPatch${Patchnum}:     ${new_patchname}" ${specfile}

	#add changelog in spec file
	changelog_line=$(grep -n '^%changelog' gazelle.spec | cut -f1 -d':')
	changelog_data=$(date +"%a %b %d %Y")
	changelog_version=$(grep '^Version' gazelle.spec | awk '{print $2}')

	if [ -z "$done_once" ];then
		sed -i "${changelog_line} G" ${specfile}
	fi
	sed -i "${changelog_line} a- ${gitmsg}" ${specfile}

	mv ${workdir}/${patchname} ./${new_patchname}

	if [ -z "$done_once" ];then
		done_once=1
	fi
done

sed -i "${release_line}s/[0-9]*$/${release}/g" ${specfile}
sed -i "${changelog_line} a* ${changelog_data} ${USER} <${EMAIL}> - ${changelog_version}-${release}" ${specfile}

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
