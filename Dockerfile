FROM python:3.11

WORKDIR /repovul

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  build-essential \
  clang \
  cmake \
  curl \
  git \
  && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m repovuluser
USER repovuluser
ENV HOME=/home/repovuluser
WORKDIR $HOME/repovul

# Install ASDF
ENV ASDF_DATA_DIR=$HOME/.asdf
RUN git clone https://github.com/asdf-vm/asdf.git $ASDF_DATA_DIR --branch v0.14.0 --depth 1
ENV PATH="$ASDF_DATA_DIR/bin:$ASDF_DATA_DIR/shims:$PATH"

COPY --chown=repovuluser:repovuluser .tool-versions ./

# Install Ruby using ASDF
RUN asdf plugin add ruby \
  && asdf install

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="$HOME/.local/bin:$PATH"

COPY --chown=repovuluser:repovuluser . .
RUN poetry install --no-interaction --no-ansi

# Install linguist
RUN bundle install

# Create "rv" alias
RUN echo "alias rv='poetry run rv'" >> $HOME/.bashrc