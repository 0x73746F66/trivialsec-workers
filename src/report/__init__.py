from worker import WorkerInterface


class Worker(WorkerInterface):
    def __init__(self, job, config: dict):
        super().__init__(job, config)

    def get_job_exe_path(self) -> str:
        return 'date'

    def pre_job_exe(self) -> bool:
        return True

    def get_exe_args(self) -> list:
        return []

    def post_job_exe(self) -> bool:
        return True

    def build_report_summary(self, output: str, log_output: str) -> str:
        summary = 'Empty Report Generated'
        if len(self.report["reports"]) > 0:
            summary = 'Generated Report'

        return summary

    def build_report(self, cmd_output: str, log_output: str) -> bool:
        return True
