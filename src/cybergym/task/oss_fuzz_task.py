from cybergym.task.arvo_task import prepare_arvo_files
from cybergym.task.mask import mask_task_id
from cybergym.task.types import Task, TaskConfig, generate_agent_id_and_checksum
from cybergym.utils import get_oss_fuzz_id


def generate_oss_fuzz_task(config: TaskConfig) -> Task:
    """
    Generate an OSS-Fuzz task.
    """
    ossfuzz_id = get_oss_fuzz_id(config.task_id)
    ossfuzz_dir = config.data_dir / "oss-fuzz" / ossfuzz_id

    agent_facing_id = mask_task_id(config.task_id) if config.mask_map_path else config.task_id
    agent_id, checksum = generate_agent_id_and_checksum(agent_facing_id, config.salt, config.agent_id)

    prepare_arvo_files(
        config.out_dir,
        ossfuzz_dir,
        agent_facing_id,
        config.server,
        agent_id,
        checksum,
        config.difficulty,
        config.with_flag,
    )

    return Task(
        task_id=config.task_id,
        agent_id=agent_id,
        checksum=checksum,
        server=config.server,
        difficulty=config.difficulty,
        with_flag=config.with_flag,
    )


def generate_oss_fuzz_latest_task(config: TaskConfig) -> Task:
    """
    Generate an OSS-Fuzz-Latest task.
    """
    ossfuzz_id = get_oss_fuzz_id(config.task_id)
    ossfuzz_dir = config.data_dir / "oss-fuzz-latest" / ossfuzz_id

    agent_facing_id = mask_task_id(config.task_id) if config.mask_map_path else config.task_id
    agent_id, checksum = generate_agent_id_and_checksum(agent_facing_id, config.salt, config.agent_id)

    prepare_arvo_files(
        config.out_dir,
        ossfuzz_dir,
        agent_facing_id,
        config.server,
        agent_id,
        checksum,
        config.difficulty,
        config.with_flag,
    )

    return Task(
        task_id=config.task_id,
        agent_id=agent_id,
        checksum=checksum,
        server=config.server,
        difficulty=config.difficulty,
        with_flag=config.with_flag,
    )
