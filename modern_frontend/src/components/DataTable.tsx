import { useCallback, useRef, useState } from "react";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnSizingState,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronsUpDown, GripVertical } from "lucide-react";
import { useT } from "../i18n/context";

interface DataTableProps<T> {
  columns: ColumnDef<T, unknown>[];
  data: T[];
  getRowId?: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedRowId?: string;
  emptyText?: string;
  /** Enable column resize handles. Columns must have a `size` defined for this to take effect. */
  resizableColumns?: boolean;
  /** Minimum column width in pixels when resizing. */
  minColumnWidth?: number;
}

export function DataTable<T>({
  columns,
  data,
  getRowId,
  onRowClick,
  selectedRowId,
  emptyText,
  resizableColumns = false,
  minColumnWidth = 48,
}: DataTableProps<T>) {
  const t = useT();
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>({});
  const tableRef = useRef<HTMLTableElement>(null);
  const isResizing = useRef(false);

  const handleColumnSizingChange = useCallback(
    (updater: ColumnSizingState | ((prev: ColumnSizingState) => ColumnSizingState)) => {
      isResizing.current = true;
      setColumnSizing(updater);
    },
    [],
  );

  const table = useReactTable({
    data,
    columns,
    state: {
      sorting,
      ...(resizableColumns ? { columnSizing } : {}),
    },
    onSortingChange: setSorting,
    onColumnSizingChange: resizableColumns ? handleColumnSizingChange : undefined,
    enableColumnResizing: resizableColumns,
    columnResizeMode: "onChange",
    defaultColumn: resizableColumns ? { minSize: minColumnWidth } : undefined,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId,
  });

  const resolvedEmptyText = emptyText ?? t("common.noRecords");

  return (
    <div className="table-scroll">
      <table ref={tableRef} className={`data-table${resizableColumns ? " resizable-table" : ""}`} style={resizableColumns ? { width: table.getTotalSize() } : undefined}>
        <thead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id}>
              {group.headers.map((header) => {
                const sorted = header.column.getIsSorted();
                const resizeHandler = resizableColumns ? header.getResizeHandler() : undefined;
                return (
                  <th
                    key={header.id}
                    style={resizableColumns ? { width: header.getSize(), position: "relative" } : undefined}
                  >
                    {header.isPlaceholder ? null : (
                      <button
                        className="table-sort"
                        type="button"
                        onClick={header.column.getToggleSortingHandler()}
                        disabled={!header.column.getCanSort()}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {sorted === "asc" ? <ArrowUp size={13} /> : sorted === "desc" ? <ArrowDown size={13} /> : <ChevronsUpDown size={13} />}
                      </button>
                    )}
                    {resizeHandler && header.column.getCanResize() && (
                      <div
                        onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); resizeHandler(e); }}
                        onTouchStart={(e) => { e.preventDefault(); e.stopPropagation(); resizeHandler(e); }}
                        className="col-resize-handle"
                        title="Drag to resize column"
                      >
                        <GripVertical size={12} />
                      </div>
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              className={`${onRowClick ? "clickable-row" : ""} ${selectedRowId === row.id ? "selected-row" : ""}`}
              onClick={() => onRowClick?.(row.original)}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
              ))}
            </tr>
          ))}
          {table.getRowModel().rows.length === 0 && (
            <tr>
              <td className="empty-table" colSpan={columns.length}>{resolvedEmptyText}</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
