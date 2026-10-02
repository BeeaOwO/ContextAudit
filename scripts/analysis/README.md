# 三模型实验统计脚本

这里保存用于复现实验汇总的分析脚本：

- `build_final3.py`：从三个模型的分批结果构建旧 similarity 统计。
- `add_score_difference.py`：给旧统计增加模型分数差分布。
- `build_final4.py`：把旧统计转换为以 CDS 为判定指标的最终统计。
- `select_consensus_samples.py`：提取模型一致样本。
- `verify_final3.py`、`verify_final4.py`：检查汇总文件、行数和统计关系；`verify_final4.py` 不依赖已经删除的 `final3/`。

这些脚本最初用于项目内部的三模型实验，部分输入文件名和目录写在脚本顶部的常量中。开源仓库不包含对应实验输出；使用前请先将常量改为自己的结果路径。日常单文件 CDS 统计优先使用根目录下的 `scripts/calculate_cds.py`。
