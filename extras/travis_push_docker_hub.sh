#!/usr/bin/env bash

DOCKER_IMAGES=( nbisweden/ega-openssh )

retag_image () {
    base=$1
    from=$2
    to=$3
    push=$4
    docker pull "$base:$from"
    docker tag "$base:$from" "$base:$to"
    if [ "$push" = true ]; then
      printf 'Pushing LocalEGA image: %s\n' "$base:$to"
      docker push "$base:$to"
    fi
}

retag_images () {
    from=$1
    to=$2
    push=$3
    for img in "${DOCKER_IMAGES[@]}"; do
        retag_image "$img" "$from" "$to" "$push"
    done
}

printf '%s\n' "$DOCKER_PASSWORD" |
docker login -u "$DOCKER_USER" --password-stdin


## Travis run on dev branch and not a PR (this is after a PR has been approved)
## We assume that it is a merge push that contains the PR number in order to get the right PR tag
if  [ "$TRAVIS_BRANCH" = "master" ] &&
    [ "$TRAVIS_PULL_REQUEST" = "false" ]
then
    ## match PR number in commit message
    ## general regex "[^[:digit:]]+\#([[:digit:]]+).+"
    regex="Merge pull request \#([[:digit:]]+).+"
    if [[ "$TRAVIS_COMMIT_MESSAGE" =~ $regex ]]; then
        pr_number=${BASH_REMATCH[1]}
    fi
    retag_images "PR${pr_number}" latest true
fi

# When we push a tag we will retag latest with that tag
if  [ -n "$TRAVIS_TAG" ] &&
    [ "$TRAVIS_PULL_REQUEST" = "false" ]
then
    retag_images latest "$TRAVIS_TAG" true
fi

## This will be run inside the Integration Tests stage, thus no problem with tags
if  [ -n "$TRAVIS_PULL_REQUEST" ] &&
    [ "$TRAVIS_PULL_REQUEST" != "false" ] &&
    [ "$TRAVIS_BUILD_STAGE_NAME" = "Integration tests" ]
then
    retag_images "PR$TRAVIS_PULL_REQUEST" master false
fi
