from cybergym.task.arvo_task import prepare_arvo_files
from cybergym.task.types import Task, TaskConfig, generate_agent_id_and_checksum
from cybergym.utils import get_oss_fuzz_id


def generate_oss_fuzz_task(config: TaskConfig) -> Task:
    """
    Generate an ARVO task.
    """
    ossfuzz_id = get_oss_fuzz_id(config.task_id)
    ossfuzz_dir = config.data_dir / "oss-fuzz" / ossfuzz_id

    # Create a unique agent ID and checksum
    agent_id, checksum = generate_agent_id_and_checksum(config.task_id, config.salt, config.agent_id)

    # Prepare the output directory
    prepare_arvo_files(
        config.out_dir,
        ossfuzz_dir,
        config.task_id,
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
    Generate an ARVO task.
    """
    ossfuzz_id = get_oss_fuzz_id(config.task_id)
    ossfuzz_dir = config.data_dir / "oss-fuzz-latest" / ossfuzz_id

    # Create a unique agent ID and checksum
    agent_id, checksum = generate_agent_id_and_checksum(config.task_id, config.salt, config.agent_id)

    # Prepare the output directory
    prepare_arvo_files(
        config.out_dir,
        ossfuzz_dir,
        config.task_id,
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
