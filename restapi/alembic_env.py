"""
This is the RAPyDo version of the env.py for alembic.
It is copied into the migrations folder to create the
connection engine used by the migrate commands
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL

from restapi.connectors import Connector

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

config.set_main_option("script_location", "sql/migrations")

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = None

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    variables = Connector.services.get("sqlalchemy", {})
    url = URL.create(
        drivername=variables.get("dbtype", "postgresql"),
        username=variables.get("user"),
        password=variables.get("password"),
        host=variables.get("host"),
        port=int(variables.get("port") or "5432"),
        database=variables.get("db"),
    )
    context.configure(
        url=str(url),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    variables = Connector.services.get("sqlalchemy", {})
    url = URL.create(
        drivername=variables.get("dbtype", "postgresql"),
        username=variables.get("user"),
        password=variables.get("password"),
        host=variables.get("host"),
        port=int(variables.get("port") or "5432"),
        database=variables.get("db"),
    )
    connectable = create_engine(url, future=True)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
