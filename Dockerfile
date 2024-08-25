FROM python:3.10

WORKDIR /eyeballvul

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  build-essential \
  clang \
  cmake \
  curl \
  git \
  && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m evuser
USER evuser
ENV HOME=/home/evuser
WORKDIR $HOME/eyeballvul

# Install ASDF
ENV ASDF_DATA_DIR=$HOME/.asdf
RUN git clone https://github.com/asdf-vm/asdf.git $ASDF_DATA_DIR --branch v0.14.0 --depth 1
ENV PATH="$ASDF_DATA_DIR/bin:$ASDF_DATA_DIR/shims:$PATH"

COPY --chown=evuser:evuser .tool-versions ./

# Install Ruby using ASDF
RUN asdf plugin add ruby \
  && asdf install

# Install linguist
COPY --chown=evuser:evuser Gemfile.lock Gemfile ./
RUN bundle install

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="$HOME/.local/bin:$PATH"

# Install the project using poetry
COPY --chown=evuser:evuser . .
RUN poetry install --no-interaction --no-ansi

# Create "ev" alias
RUN echo "alias ev='poetry run ev'" >> $HOME/.bashrc
