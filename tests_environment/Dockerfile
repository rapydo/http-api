
FROM template/backend:template

ENV UTILS_VERSION 0.5.1
ENV HTTP_BRANCH travis...

RUN pip3 install --upgrade rapydo-utils==$UTILS_VERSION
RUN pip3 install --upgrade \
    git+https://github.com/rapydo/http-api.git@$HTTP_BRANCH
