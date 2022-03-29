#!/usr/bin/python3
from dis import dis
import sys
import logging
from sqlalchemy import Column, Integer, JSON, Table, Text
from sqlalchemy import create_engine, distinct
from sqlalchemy.orm import sessionmaker 
from sqlalchemy.ext.declarative import declarative_base
from IPython import embed

import networkx as nx
from networkx.drawing.nx_agraph import write_dot, graphviz_layout

Base = declarative_base()
class Command(Base):
    __tablename__ = 't_commands'

    id = Column(Integer, primary_key=True)
    runtime_uuid = Column(Text)
    timestamp = Column(Integer)
    output = Column(Text)
    cmdline = Column(Text)
    arg_idx = Column(Integer)
    decoded_argv = Column(JSON)

def db_connect(path):
    engine = create_engine('sqlite:///' + path)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

def main(db_path):
    logger = logging.getLogger("analyzer")
    session = db_connect(db_path)
    runtime_uuid_array = [uuid[0] for uuid in session.query(distinct(Command.runtime_uuid)).all()]
    logger.debug(f"length of runtime_uuid_array: {len(runtime_uuid_array)}")
    for runtime_uuid in runtime_uuid_array:
        # logger.debug(f"runtime_uuid: {runtime_uuid}")
        cmds = session.query(Command).filter(Command.runtime_uuid == runtime_uuid).order_by(Command.arg_idx.asc()).all()
        members = []
        for cmd in cmds:
            if cmd.decoded_argv['opt_name'] == 'OPT_SPECIAL_input_file':
                members.append(cmd.decoded_argv['canonical_option'][0])
        if len(members) > 0:
            print(f"{cmd.output}: {', '.join(members)}")


if __name__ == '__main__':
    logging.basicConfig(format="[%(levelname)s] (%(name)s) %(message)s")
    logging.getLogger("analyzer").setLevel(logging.DEBUG)
    main(sys.argv[1])