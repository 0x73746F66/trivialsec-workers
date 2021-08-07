from worker import WorkerInterface
"""
dirhunt --progress-disabled --max-depth 24 --not-allow-redirects --to-file dirhunt.json http://nib.com.au/
"""

class Worker(WorkerInterface):
    updated = False
    def __init__(self, job, paths :dict):
        super().__init__(job, paths)

    def get_result_filename(self) -> str:
        return ''

    def get_log_filename(self) -> str:
        return ''

    def get_archive_files(self) -> dict:
        return {}

    def get_job_exe_path(self) -> str:
        return 'echo'

    def pre_job_exe(self) -> bool:
        return True

    def get_exe_args(self) -> list:
        return [('dirhunt',)]

    def post_job_exe(self) -> bool:
        return True

    def build_report_summary(self, output :str, log_output :str) -> str:
        return 'No results'

    def build_report(self, cmd_output :str, log_output :str) -> bool:
        return True

    def analyse_report(self):
        return True
